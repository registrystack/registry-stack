//! The serve runtime: one strict YAML file with everything a deployment
//! owns: listener, verified bundle package, secret providers, caller key,
//! limits, audit. Nothing here can override governed (bundle) behavior.
//!
//! The file is read through the shared Registry Stack runtime configuration
//! loader, so its envelope, size bound, path rules, `${VAR}` substitution,
//! and secret provider declarations match every other runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, PersistentRootFault,
    MAX_AUDIT_RETAIN_DAYS, MIN_AUDIT_ROTATE_BYTES,
};
use registry_platform_config::{
    ConfigBlockError, ConfigBlockErrorKind, ListenerBind, ListenerNetworkExposure,
    LoadedRuntimeConfig, OidcClientsConfig, OidcIssuerConfig, PackageConfig, RemovedKey,
    RuntimeConfigLoader, RuntimeEnvelope, RuntimeFileCheck, SecretProvidersConfig,
};
use registry_platform_yaml::{
    escape_pointer_segment, shape_union, BoundedU32, BoundedU64, Diagnostic, ExternalId, LocalId,
    RetiredApiVersion, Severity, Source, UniqueList, Url,
};
use serde::Deserialize;

use crate::manifest::Manifest;
use crate::problem::{ProblemKind, RenderProblem};

pub const RUNTIME_API_VERSION: &str = "id.registrystack.org/formats/render/runtime/v1alpha1";
pub const RUNTIME_KIND: &str = "RenderRuntimeConfig";

const RENDER_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

/// The apiVersion a runtime file carried before its members took their
/// shared names, refused with the renames it needs.
const RETIRED_RUNTIME_API_VERSIONS: &[RetiredApiVersion<'static>] = &[RetiredApiVersion {
    api_version: "registry.registrystack.org/render-runtime/v1alpha1",
    replacement: "Write apiVersion id.registrystack.org/formats/render/runtime/v1alpha1, then \
                  rename listener.shutdownGraceSeconds to listener.shutdownGraceMilliseconds \
                  (the value times 1000), limits.maxOutputBytes to limits.maximumOutputBytes, \
                  limits.maxRequestBodyBytes to limits.maximumRequestBytes, \
                  limits.maxConcurrency to limits.maximumConcurrentRenders, and \
                  audit.retainDays to audit.retentionDays.",
}];

/// Keys an earlier runtime file carried, each refused with its replacement.
const RENDER_REMOVED_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "server",
        replacement: "Declare `listener.bind` and `listener.shutdownGraceMilliseconds` instead.",
    },
    RemovedKey {
        path: "bundle",
        replacement: "declare package.root as the absolute path of the package directory",
    },
    RemovedKey {
        path: "auth",
        replacement: "Rename `auth` to `authentication`; its members are unchanged.",
    },
    RemovedKey {
        path: "listener.shutdownGraceSeconds",
        replacement: "Declare `listener.shutdownGraceMilliseconds` instead, the value times 1000.",
    },
    RemovedKey {
        path: "limits.maxOutputBytes",
        replacement: "declare limits.maximumOutputBytes instead",
    },
    RemovedKey {
        path: "limits.maxRequestBodyBytes",
        replacement: "declare limits.maximumRequestBytes instead",
    },
    RemovedKey {
        path: "limits.maxConcurrency",
        replacement: "declare limits.maximumConcurrentRenders instead",
    },
    RemovedKey {
        path: "audit.directory",
        replacement: "declare audit.path as the absolute path of the active audit file instead",
    },
    RemovedKey {
        path: "audit.integrityKeyRef",
        replacement: "remove it; audit entries are not hash-chained, so no integrity key is read",
    },
    RemovedKey {
        path: "audit.maxSegmentBytes",
        replacement: "declare audit.rotateBytes instead",
    },
    RemovedKey {
        path: "audit.retainDays",
        replacement: "declare audit.retentionDays instead",
    },
];

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RenderRuntime {
    pub api_version: String,
    pub kind: String,
    pub listener: ListenerRuntime,
    /// The verified bundle package Render serves.
    pub package: PackageConfig,
    /// Providers for secret references. Omit when the authentication mode uses
    /// no secret references.
    #[serde(default)]
    pub secret_providers: SecretProvidersConfig,
    pub authentication: AuthenticationRuntime,
    #[serde(default)]
    pub limits: LimitsRuntime,
    pub audit: AuditRuntime,
    /// Optional document sealing. Omit it and Render loads no signer, makes
    /// no timestamp call, and cannot seal any document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningRuntime>,
}

impl RenderRuntime {
    /// The seal that `seal_id` binds, or `None` when the runtime has no
    /// `signing` block or binds no such seal.
    #[must_use]
    pub fn seal(&self, seal_id: &str) -> Option<&SealRuntime> {
        self.signing
            .as_ref()?
            .seals
            .iter()
            .find_map(|(id, seal)| (id.as_str() == seal_id).then_some(seal))
    }

    /// The seal the document type `document_id` is issued under: the seal id
    /// the bundle manifest declares on the document type, resolved through
    /// `signing.seals`.
    ///
    /// `None` means the document cannot be sealed: the document type is not
    /// in `manifest`, it declares no `seal`, or the runtime has no `signing`
    /// block. A document type that declares a seal the runtime does not bind
    /// is refused before serving starts ([`validate_seal_bindings`] and
    /// `registry-render check`), so on a validated pair `None` never hides a
    /// misconfiguration. The seal route that uses this takes no seal name from
    /// the caller; the bundle alone decides which seal issues which document.
    #[must_use]
    pub fn seal_for(&self, manifest: &Manifest, document_id: &str) -> Option<&SealRuntime> {
        let document = manifest
            .documents
            .iter()
            .find(|document| document.id == document_id)?;
        self.seal(document.seal.as_deref()?)
    }
}

/// The shortest grace a runtime may declare: zero would drop the renders
/// and seals in flight the moment SIGTERM arrives.
pub const MINIMUM_SHUTDOWN_GRACE_MILLISECONDS: u64 = 1_000;

/// The longest grace a runtime may declare. Shutdown waits the grace for
/// renders and seals in flight and then the same again for connections, so
/// the bound keeps that sum representable as well as operationally sane.
pub const MAXIMUM_SHUTDOWN_GRACE_MILLISECONDS: u64 = 3_600_000;

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListenerRuntime {
    /// Loopback, private, or link-local address to listen on. A public or
    /// all-interfaces bind is refused when the file is read. TLS is the
    /// proxy's job, not Render's.
    pub bind: ListenerBind,
    #[serde(default)]
    pub network_exposure: ListenerNetworkExposure,
    /// Time allowed for renders and seals in flight to finish at shutdown,
    /// in milliseconds. Open connections get the same again.
    #[serde(default = "default_shutdown_grace")]
    pub shutdown_grace_milliseconds:
        BoundedU64<MINIMUM_SHUTDOWN_GRACE_MILLISECONDS, MAXIMUM_SHUTDOWN_GRACE_MILLISECONDS>,
}

impl ListenerRuntime {
    /// Wildcard container listeners require an explicit private-network declaration.
    pub fn bind_allowed(&self) -> bool {
        let address = self.bind.socket_addr();
        bind_allowed(address)
            || (self.network_exposure == ListenerNetworkExposure::ContainerPrivate
                && address.ip().is_unspecified())
    }

    /// `shutdownGraceMilliseconds` as a duration.
    #[must_use]
    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_millis(self.shutdown_grace_milliseconds.get())
    }
}

/// Whether Render may listen on `addr`: loopback, private, and link-local
/// addresses only.
fn bind_allowed(addr: std::net::SocketAddr) -> bool {
    match addr {
        std::net::SocketAddr::V4(a) => {
            let ip = a.ip();
            ip.is_loopback() || ip.is_private() || ip.is_link_local()
        }
        std::net::SocketAddr::V6(a) => {
            let ip = a.ip();
            ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
        }
    }
}

/// Render never listens on a public address: TLS termination and network
/// position belong to the deployment's proxy. Loopback, private, and
/// link-local addresses pass; unspecified (all interfaces) and public
/// addresses are refused with a named startup problem, an explicit refusal
/// instead of an accidental exposure.
pub fn validate_bind(addr: std::net::SocketAddr) -> Result<(), RenderProblem> {
    if bind_allowed(addr) {
        Ok(())
    } else {
        Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!(
                "listener.bind {addr} is not a loopback or private address; Render never \
                 listens publicly or on all interfaces; terminate TLS and position the \
                 service on a proxy, and bind its private address here"
            ),
        ))
    }
}

fn default_shutdown_grace(
) -> BoundedU64<MINIMUM_SHUTDOWN_GRACE_MILLISECONDS, MAXIMUM_SHUTDOWN_GRACE_MILLISECONDS> {
    BoundedU64::new(30_000).expect("the default grace is within its bounds")
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthenticationRuntime {
    /// Secret reference to the caller API key, under a declared provider.
    /// Omit when OIDC authentication is configured.
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_config::SecretReference")
    )]
    #[serde(default, deserialize_with = "present_auth_member")]
    pub api_key_ref: Option<String>,
    #[serde(default, deserialize_with = "present_auth_member")]
    #[cfg_attr(feature = "schema", schemars(with = "OidcRuntime"))]
    pub oidc: Option<OidcRuntime>,
}

fn present_auth_member<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Serving-adapter OIDC configuration. The pure rendering library never reads it.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OidcRuntime {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub provider: OidcIssuerConfig,
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-clients"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub clients: OidcClientsConfig,
}

/// The longest render a runtime may allow.
pub const MAXIMUM_RENDER_TIMEOUT_SECONDS: u64 = 3_600;
/// The produced PDF never exceeds the renderer's own ceiling.
const MAXIMUM_OUTPUT_BYTES: u64 = crate::render::DEFAULT_MAX_OUTPUT_BYTES as u64;
/// The request body ceiling no runtime may raise past: 64 MiB.
const MAXIMUM_REQUEST_BYTES: u64 = 64 * 1024 * 1024;
const MAXIMUM_CONCURRENT_RENDERS: u64 = 64;

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LimitsRuntime {
    /// Wall-clock budget per render, in seconds; the worker is killed at
    /// this bound.
    #[serde(default = "default_render_timeout")]
    pub render_timeout_seconds: BoundedU64<1, MAXIMUM_RENDER_TIMEOUT_SECONDS>,
    /// Largest PDF a render may produce, in bytes.
    #[serde(default = "default_maximum_output_bytes")]
    pub maximum_output_bytes: BoundedU64<1, MAXIMUM_OUTPUT_BYTES>,
    /// Largest request body (data and base64 assets), in bytes. The httpsec
    /// default is 1 MiB; renders with photos need a conscious, bounded raise.
    #[serde(default = "default_maximum_request_bytes")]
    pub maximum_request_bytes: BoundedU64<1, MAXIMUM_REQUEST_BYTES>,
    /// Most renders in flight at once. Default: the CPU count, at most 8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<1, MAXIMUM_CONCURRENT_RENDERS>")
    )]
    pub maximum_concurrent_renders: Option<BoundedU64<1, MAXIMUM_CONCURRENT_RENDERS>>,
}

impl Default for LimitsRuntime {
    fn default() -> Self {
        Self {
            render_timeout_seconds: default_render_timeout(),
            maximum_output_bytes: default_maximum_output_bytes(),
            maximum_request_bytes: default_maximum_request_bytes(),
            maximum_concurrent_renders: None,
        }
    }
}

impl LimitsRuntime {
    /// `renderTimeoutSeconds` as a duration.
    #[must_use]
    pub fn render_timeout(&self) -> Duration {
        Duration::from_secs(self.render_timeout_seconds.get())
    }

    /// `maximumOutputBytes` as a length.
    #[must_use]
    pub fn output_bytes(&self) -> usize {
        to_length(self.maximum_output_bytes.get())
    }

    /// `maximumRequestBytes` as a length.
    #[must_use]
    pub fn request_bytes(&self) -> usize {
        to_length(self.maximum_request_bytes.get())
    }

    /// `maximumConcurrentRenders`, or the CPU count capped at 8 when the
    /// file leaves it out.
    #[must_use]
    pub fn concurrent_renders(&self) -> usize {
        self.maximum_concurrent_renders
            .map_or_else(default_concurrent_renders, |renders| {
                to_length(renders.get())
            })
    }
}

/// Every limit above is at most 64 MiB, which fits `usize` on every target
/// the workspace builds for.
fn to_length(value: u64) -> usize {
    usize::try_from(value).expect("a Render runtime limit fits usize")
}

pub fn default_render_timeout_seconds() -> u64 {
    20
}

fn default_render_timeout() -> BoundedU64<1, MAXIMUM_RENDER_TIMEOUT_SECONDS> {
    BoundedU64::new(default_render_timeout_seconds())
        .expect("the default render timeout is within its bounds")
}

fn default_maximum_output_bytes() -> BoundedU64<1, MAXIMUM_OUTPUT_BYTES> {
    BoundedU64::new(MAXIMUM_OUTPUT_BYTES).expect("the output ceiling is within its bounds")
}

fn default_maximum_request_bytes() -> BoundedU64<1, MAXIMUM_REQUEST_BYTES> {
    BoundedU64::new(8 * 1024 * 1024).expect("the default request ceiling is within its bounds")
}

fn default_concurrent_renders() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(2)
}

/// The shortest attempt a timestamp authority call may be given.
pub const MINIMUM_TIMESTAMP_ATTEMPT_MILLISECONDS: u64 = 1_000;
/// The longest attempt a timestamp authority call may be given.
pub const MAXIMUM_TIMESTAMP_ATTEMPT_MILLISECONDS: u64 = 60_000;
/// The attempt a timestamp authority call is given when the file says nothing.
const DEFAULT_TIMESTAMP_ATTEMPT_MILLISECONDS: u64 = 10_000;

/// Document sealing: the seals this deployment can apply. A seal is a PAdES
/// signature made with the institution's own key. Which document types use
/// which seal is decided in the bundle manifest (`seal` on a document type),
/// never by the caller.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SigningRuntime {
    /// The seals, keyed by the local identifier the bundle manifest's `seal`
    /// names. At least one seal is required: omit `signing` to turn sealing
    /// off.
    pub seals: BTreeMap<LocalId, SealRuntime>,
}

/// One seal: the key material, the certificate chain, the timestamp policy,
/// and the clients allowed to use it.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SealRuntime {
    /// Secret reference to the seal's private key as a JSON Web Key, under a
    /// declared provider. A reference, never a path to a key file. Local key
    /// files suit development and pilots; the serving process alone reads
    /// the key.
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_config::SecretReference")
    )]
    pub private_key_ref: String,
    /// Absolute path of the PEM certificate chain file, the seal's own
    /// certificate first, then each issuer. It is absolute like Render's
    /// other runtime paths, so a runtime file names deployment locations,
    /// not locations relative to wherever the file was copied.
    #[cfg_attr(feature = "schema", schemars(with = "PathBuf"))]
    pub certificate_chain_file: PathBuf,
    /// The RFC 3161 timestamp authority that timestamps each seal (PAdES
    /// B-T), so the seal keeps validating after its certificate expires.
    /// Exactly one of `timestampAuthority` and `withoutTimestamp` is
    /// required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "TimestampAuthorityRuntime"))]
    pub timestamp_authority: Option<TimestampAuthorityRuntime>,
    /// Seal without a timestamp (PAdES B-B). The only value states the
    /// consequence the operator accepts: a seal without a timestamp stops
    /// validating when its certificate expires, which is usually before the
    /// document stops mattering. Exactly one of `timestampAuthority` and
    /// `withoutTimestamp` is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "WithoutTimestamp"))]
    pub without_timestamp: Option<WithoutTimestamp>,
    /// The OIDC clients allowed to seal with this seal: a list of at least
    /// one client, each also admitted by `authentication.oidc.allowedClients`. There is
    /// no `unrestricted` form and no wildcard: a seal issues documents in the
    /// institution's name, so every seal-capable client is named. Keep these
    /// clients separate from any citizen-facing client.
    #[cfg_attr(feature = "schema", schemars(with = "UniqueList<ExternalId>"))]
    pub allowed_clients: SealClients,
    /// `test-only` marks a seal made with a test certificate: the template is
    /// told so and prints the seal as a test seal. Omit it for a production
    /// seal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "SealTrust"))]
    pub trust: Option<SealTrust>,
}

impl SealRuntime {
    /// Whether the OIDC client `client_id` may seal with this seal.
    #[must_use]
    pub fn allows_client(&self, client_id: &str) -> bool {
        self.allowed_clients
            .as_slice()
            .iter()
            .any(|allowed| allowed == client_id)
    }

    /// Whether the seal is declared test-only.
    #[must_use]
    pub fn is_test_only(&self) -> bool {
        self.trust == Some(SealTrust::TestOnly)
    }
}

/// The RFC 3161 timestamp authority a seal uses.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TimestampAuthorityRuntime {
    /// Absolute `https` URL of the authority. `http` is accepted only for a
    /// loopback host (`localhost`, `127.0.0.0/8`, `[::1]`), for a test
    /// authority on the same machine.
    pub url: Url,
    /// Time allowed for one request to the authority, in milliseconds.
    #[serde(default = "default_timestamp_attempt")]
    pub attempt_timeout_milliseconds:
        BoundedU64<MINIMUM_TIMESTAMP_ATTEMPT_MILLISECONDS, MAXIMUM_TIMESTAMP_ATTEMPT_MILLISECONDS>,
}

impl TimestampAuthorityRuntime {
    /// `attemptTimeoutMilliseconds` as a duration.
    #[must_use]
    pub fn attempt_timeout(&self) -> Duration {
        Duration::from_millis(self.attempt_timeout_milliseconds.get())
    }
}

fn default_timestamp_attempt(
) -> BoundedU64<MINIMUM_TIMESTAMP_ATTEMPT_MILLISECONDS, MAXIMUM_TIMESTAMP_ATTEMPT_MILLISECONDS> {
    BoundedU64::new(DEFAULT_TIMESTAMP_ATTEMPT_MILLISECONDS)
        .expect("the default attempt is within its bounds")
}

/// The acknowledgement a seal needs to go without a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum WithoutTimestamp {
    /// The seal carries no timestamp, so it stops validating when its
    /// certificate expires.
    SealStopsValidatingWhenCertificateExpires,
}

/// How a seal is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SealTrust {
    /// A seal made with a test certificate; documents print it as a test
    /// seal.
    TestOnly,
}

/// The clients allowed to use a seal, as `allowedClients` writes them. A
/// single value instead of a list is read only so that its refusal can state
/// why a seal is never unrestricted; the runtime check refuses it, so a
/// runtime that loaded holds a non-empty list.
#[derive(Debug, Clone)]
pub struct SealClients {
    clients: Vec<String>,
    written_as_list: bool,
}

impl SealClients {
    /// The listed client identifiers.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.clients
    }
}

/// A value in the position of the list, read only to be refused.
struct NotAList;

impl<'de> Deserialize<'de> for NotAList {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|_| Self)
    }
}

enum SealClientsWire {
    Scalar(NotAList),
    List(UniqueList<ExternalId>),
}

shape_union!(SealClientsWire { scalar => Scalar, list => List });

impl<'de> Deserialize<'de> for SealClients {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match SealClientsWire::deserialize(deserializer)? {
            SealClientsWire::Scalar(NotAList) => Self {
                clients: Vec::new(),
                written_as_list: false,
            },
            SealClientsWire::List(list) => Self {
                clients: list.into_iter().map(String::from).collect(),
                written_as_list: true,
            },
        })
    }
}

/// The largest `audit.rotateBytes` the shared audit writer accepts.
const MAXIMUM_AUDIT_ROTATE_BYTES: u64 = u32::MAX as u64;

/// The audit block every Registry Stack product shares: a `file` (the
/// default) or `stdout` destination, with rotation and retention for a file.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditRuntime {
    /// Where audit lines go: `file` or `stdout`.
    #[serde(default)]
    pub destination: AuditDestinationKind,
    /// The absolute path of the active audit file, for a `file` destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "PathBuf"))]
    pub path: Option<PathBuf>,
    /// Size at which the active file rotates, in bytes, for a `file`
    /// destination. Default: 100 MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>")
    )]
    pub rotate_bytes: Option<BoundedU64<MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>>,
    /// Days a rotated file is kept, for a `file` destination. Default: 90.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU32<1, MAX_AUDIT_RETAIN_DAYS>")
    )]
    pub retention_days: Option<BoundedU32<1, MAX_AUDIT_RETAIN_DAYS>>,
}

impl AuditRuntime {
    /// The destination the shared audit writer builds from this block.
    fn settings(&self) -> Result<AuditDestination, AuditDestinationError> {
        AuditDestination::from_settings(
            self.destination,
            self.path.clone(),
            self.rotate_bytes.map(BoundedU64::get),
            self.retention_days.map(BoundedU32::get),
        )
    }

    /// The validated destination the audit writer opens.
    pub fn destination(&self) -> Result<AuditDestination, RenderProblem> {
        self.settings().map_err(|error| {
            RenderProblem::new(ProblemKind::RuntimeInvalid, audit_finding(&error).message)
        })
    }
}

/// The loader for the Render runtime file, with its removed keys and its
/// retired apiVersion.
#[must_use]
pub const fn runtime_loader() -> RuntimeConfigLoader {
    RuntimeConfigLoader::new(RENDER_RUNTIME_ENVELOPE)
        .removed_keys(RENDER_REMOVED_KEYS)
        .retired_api_versions(RETIRED_RUNTIME_API_VERSIONS)
        .require_trusted_ownership()
}

/// What an offline check of one runtime file found.
#[derive(Debug)]
pub struct RuntimeCheck {
    /// Every finding, each naming the file as `path` was given.
    pub diagnostics: Vec<Diagnostic>,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
    /// The signature space each seal reserves, by seal id, for every chain
    /// the check read and could size: only with `substitute`, which reads
    /// the chain files.
    /// The file declares seals whose chain files were not read, because the
    /// check ran without `substitute`.
    pub seal_chains_not_read: bool,
    pub seal_capacities: BTreeMap<String, usize>,
}

/// Check the runtime file at the absolute `path` as `registry-render serve`
/// reads it, with no package, secret material, or listener (CFG-CHECK-1).
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only: the value checks of a member that
/// holds one are skipped, because they need the substituted text.
///
/// With `audit_root`, the check also proves that the audit file resolves
/// under that directory, the one the deployment mounts as persistent
/// storage (the container preflight proof).
#[must_use]
pub fn check_runtime(path: &Path, substitute: bool, audit_root: Option<&Path>) -> RuntimeCheck {
    check_runtime_with_bundle(path, substitute, audit_root, None)
}

/// [`check_runtime`], and with the `manifest` of the bundle the runtime will
/// serve, the seal bindings of both files together: a document type that
/// names a seal the runtime does not bind is an error, and a runtime seal no
/// document type names is a warning, each placed in the runtime file. With no
/// `signing` block sealing is off, and a manifest that names seals adds one
/// warning that its sealed document types render unsealed.
#[must_use]
pub fn check_runtime_with_bundle(
    path: &Path,
    substitute: bool,
    audit_root: Option<&Path>,
    manifest: Option<&Manifest>,
) -> RuntimeCheck {
    read_runtime(path, substitute, audit_root, manifest, substitute).1
}

/// Load and validate a runtime file through the shared loader, with the
/// process environment, as serve does at startup. Returns the runtime and
/// the `sha256:` digest of its effective configuration; a refusal carries
/// every finding, each positioned in the file and naming its fix.
pub fn load(path: &Path) -> Result<(RenderRuntime, String), RenderProblem> {
    match read_runtime(path, true, None, None, false) {
        (Some(loaded), _) => Ok((loaded.config, loaded.effective_digest)),
        (None, check) => {
            let detail = if check.unavailable {
                "the runtime configuration could not be read"
            } else {
                "the runtime configuration was refused"
            };
            Err(RenderProblem::new(ProblemKind::RuntimeInvalid, detail)
                .with_diagnostics(check.diagnostics))
        }
    }
}

/// The file read by the shared loader, then the members the loader cannot
/// judge checked: the bind, the package and secret provider blocks, the
/// caller key reference, and the audit destination, and, with `audit_root`,
/// the audit containment proof. With `seal_chains`, each seal's certificate
/// chain file is read and checked without its key ([`crate::seal::check_chain`]);
/// `check --environment` asks for it, and serve does not, since loading a
/// seal reads the chain and the key together. The configuration is returned
/// only when nothing was found.
fn read_runtime(
    path: &Path,
    substitute: bool,
    audit_root: Option<&Path>,
    manifest: Option<&Manifest>,
    seal_chains: bool,
) -> (Option<LoadedRuntimeConfig<RenderRuntime>>, RuntimeCheck) {
    let check = runtime_loader().check_offline::<RenderRuntime>(path, substitute, stand_in_for);
    let mut diagnostics = check.diagnostics.clone();
    let mut unavailable = check.unavailable;
    let mut seal_capacities = BTreeMap::new();
    if let Some(loaded) = &check.loaded {
        let mut audit_refused = false;
        for finding in findings(&loaded.config) {
            let audit_deferred =
                finding.pointer.starts_with("/audit") && check.defers("/audit/destination");
            if !check.defers(&finding.pointer) && !audit_deferred {
                audit_refused |= finding.pointer.starts_with("/audit");
                diagnostics.push(check.error_at(
                    RUNTIME_KIND,
                    finding.code,
                    &finding.pointer,
                    finding.message,
                    finding.action,
                ));
            }
        }
        if let Some(manifest) = manifest {
            for binding in seal_binding_findings(&loaded.config, manifest) {
                let finding = binding.finding;
                let mut diagnostic = if binding.at_key {
                    check.error_at_key(
                        RUNTIME_KIND,
                        finding.code,
                        &finding.pointer,
                        finding.message,
                        finding.action,
                    )
                } else {
                    check.error_at(
                        RUNTIME_KIND,
                        finding.code,
                        &finding.pointer,
                        finding.message,
                        finding.action,
                    )
                };
                diagnostic.severity = binding.severity;
                diagnostics.push(diagnostic);
            }
        }
        if let (true, Some(signing)) = (seal_chains, &loaded.config.signing) {
            let now = time::OffsetDateTime::now_utc();
            for (id, seal) in &signing.seals {
                let pointer = format!("{}/certificateChainFile", seal_pointer(id.as_str()));
                if check.defers(&pointer) {
                    continue;
                }
                let chain = crate::seal::check_chain(id.as_str(), seal, now);
                if let Some(capacity) = chain.contents_capacity {
                    seal_capacities.insert(id.as_str().to_owned(), capacity);
                }
                for finding in chain.findings {
                    let mut diagnostic = check.error_at(
                        RUNTIME_KIND,
                        finding.code,
                        &pointer,
                        finding.message,
                        finding.action.to_owned(),
                    );
                    diagnostic.severity = finding.severity;
                    diagnostics.push(diagnostic);
                }
            }
        }
        if let (Some(root), false) = (audit_root, audit_refused) {
            match prove_audit_under(&check, &loaded.config.audit, root) {
                Proof::Held => {}
                Proof::Refused(finding) => diagnostics.push(check.error_at(
                    RUNTIME_KIND,
                    finding.code,
                    &finding.pointer,
                    finding.message,
                    finding.action,
                )),
                Proof::RootUnreadable => {
                    unavailable = true;
                    let mut diagnostic = Diagnostic::error(
                        "render.check.audit-root-unreadable",
                        "",
                        "the --require-audit-under directory could not be read as a directory",
                        "Check that the directory exists and that this user may read it, then \
                         run the check again.",
                    );
                    diagnostic.source = Some(Source {
                        file: root.display().to_string(),
                        line: None,
                        column: None,
                    });
                    diagnostics.push(diagnostic);
                }
            }
        }
    }
    let seal_chains_not_read = !seal_chains
        && check
            .loaded
            .as_ref()
            .is_some_and(|loaded| loaded.config.signing.is_some());
    // A warning reports a finding but does not refuse the file.
    let loaded = check
        .loaded
        .filter(|_| diagnostics.iter().all(|d| d.severity != Severity::Error));
    (
        loaded,
        RuntimeCheck {
            diagnostics,
            unavailable,
            seal_capacities,
            seal_chains_not_read,
        },
    )
}

/// What the audit containment proof found.
enum Proof {
    Held,
    Refused(Finding),
    /// The directory the proof was asked for could not be read.
    RootUnreadable,
}

/// Prove that the audit file resolves under `root` once both are resolved
/// through the filesystem. A destination that holds an unsubstituted
/// expression has no value to prove, and a stdout destination no path.
fn prove_audit_under(
    check: &RuntimeFileCheck<RenderRuntime>,
    audit: &AuditRuntime,
    root: &Path,
) -> Proof {
    let deferred = ["/audit/destination", "/audit/path"]
        .into_iter()
        .find(|pointer| check.defers(pointer));
    if let Some(pointer) = deferred {
        return Proof::Refused(Finding {
            code: "render.runtime.audit-proof-needs-environment",
            pointer: pointer.to_owned(),
            message: "the member holds a substitution expression, so the audit containment \
                      proof has no value to prove"
                .to_owned(),
            action: "Run the check with --environment, in the environment the service runs in."
                .to_owned(),
        });
    }
    let file = match audit.settings() {
        Ok(AuditDestination::File(file)) => file,
        Ok(_) => {
            return Proof::Refused(Finding {
                code: "render.runtime.audit-stdout-unprovable",
                pointer: "/audit/destination".to_owned(),
                message: "audit.destination is stdout, which has no path to prove under the \
                          --require-audit-under directory"
                    .to_owned(),
                action: "Write audit to a file under that directory, or run the check without \
                         --require-audit-under."
                    .to_owned(),
            })
        }
        // The audit block's own refusal is already reported.
        Err(_) => return Proof::Held,
    };
    let refused = |code, message: &str, action: &str| {
        Proof::Refused(Finding {
            code,
            pointer: "/audit/path".to_owned(),
            message: message.to_owned(),
            action: action.to_owned(),
        })
    };
    match registry_platform_audit::require_audit_under(file.path(), root) {
        Ok(()) => Proof::Held,
        Err(PersistentRootFault::Root) => Proof::RootUnreadable,
        Err(PersistentRootFault::Destination) => refused(
            "render.runtime.audit-path-unresolved",
            "the audit file could not be resolved through the directories that exist",
            "Make the existing directories above the audit file readable by this user, and \
             replace any broken link among them.",
        ),
        Err(PersistentRootFault::Outside) => refused(
            "render.runtime.audit-outside-root",
            "the audit file resolves outside the --require-audit-under directory",
            "Move audit.path under that directory, or mount the directory that holds the audit \
             file as persistent storage and name it instead.",
        ),
    }
}

/// One refusal of a member the shared loader accepted.
struct Finding {
    code: &'static str,
    pointer: String,
    message: String,
    action: String,
}

fn findings(runtime: &RenderRuntime) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !runtime.listener.bind_allowed() {
        findings.push(Finding {
            code: "render.runtime.public-bind",
            pointer: "/listener/bind".to_owned(),
            message: "listener.bind is not a loopback, private, or link-local address; Render \
                      never listens publicly or on all interfaces"
                .to_owned(),
            action: "Bind the private address your proxy forwards to; the proxy terminates TLS."
                .to_owned(),
        });
    }
    let blocks = [runtime.package.check()];
    findings.extend(
        blocks
            .iter()
            .filter_map(|result| result.as_ref().err())
            .map(block_finding),
    );
    let needs_secrets = runtime.authentication.oidc.as_ref().is_none_or(|oidc| {
        matches!(
            oidc.provider.jwks_source,
            registry_platform_config::JwksSource::Static { .. }
        )
    });
    if needs_secrets
        || runtime.signing.is_some()
        || runtime.secret_providers.file.is_some()
        || runtime.secret_providers.environment.is_some()
    {
        if let Err(error) = runtime.secret_providers.check() {
            findings.push(block_finding(&error));
        }
    }
    match (&runtime.authentication.oidc, &runtime.authentication.api_key_ref) {
        (Some(oidc), None) => {
            findings.extend([oidc.provider.check("authentication.oidc", true), oidc.clients.check("authentication.oidc")].iter().filter_map(|result| result.as_ref().err()).map(block_finding));
            if let registry_platform_config::JwksSource::Static { document_ref } = &oidc.provider.jwks_source {
                if let Err(error) = runtime.secret_providers.check_reference("authentication.oidc.jwksSource.documentRef", document_ref) { findings.push(block_finding(&error)); }
            }
        }
        (None, Some(api_key_ref)) => {
            if let Err(error) = runtime.secret_providers.check_reference("authentication.apiKeyRef", api_key_ref) { findings.push(block_finding(&error)); }
        }
        _ => findings.push(Finding { code: "render.runtime.authentication", pointer: "/authentication".to_owned(), message: "authentication must configure exactly one of oidc or apiKeyRef".to_owned(), action: "Configure authentication.oidc for the Render resource, or one legacy apiKeyRef; remove the other mode.".to_owned() }),
    }
    if let Err(error) = runtime.audit.settings() {
        findings.push(audit_finding(&error));
    }
    if let Some(signing) = &runtime.signing {
        findings.extend(signing_findings(runtime, signing));
    }
    findings
}

/// The pointer of the seal `id` in the runtime file.
fn seal_pointer(id: &str) -> String {
    format!("/signing/seals/{}", escape_pointer_segment(id))
}

/// Every refusal of the `signing` block that needs no bundle: OIDC
/// authentication, the secret reference, the certificate path, the
/// timestamp policy, and the client list.
fn signing_findings(runtime: &RenderRuntime, signing: &SigningRuntime) -> Vec<Finding> {
    let mut findings = Vec::new();
    let finding = |code: &'static str, pointer: String, message: String, action: &str| Finding {
        code,
        pointer,
        message,
        action: action.to_owned(),
    };
    // With the legacy key, `authentication` already carries its own refusal when it is
    // neither mode; only the key mode makes sealing impossible.
    if runtime.authentication.oidc.is_none() && runtime.authentication.api_key_ref.is_some() {
        findings.push(finding(
            "render.runtime.signing-requires-oidc",
            "/signing".to_owned(),
            "signing needs OIDC authentication: the legacy API key cannot say which client is \
             sealing, so it can never be allowed to seal"
                .to_owned(),
            "Configure authentication.oidc and name the sealing clients in each seal's allowedClients, or \
             remove the signing block.",
        ));
    }
    if signing.seals.is_empty() {
        findings.push(finding(
            "render.runtime.no-seals",
            "/signing/seals".to_owned(),
            "signing.seals declares no seal".to_owned(),
            "Declare at least one seal, or remove the signing block to leave sealing off.",
        ));
    }
    let admitted: Option<BTreeSet<&str>> = runtime.authentication.oidc.as_ref().and_then(|oidc| {
        // An empty list is how the token verifier holds `unrestricted`.
        let clients = &oidc.clients.allowed_clients;
        (!clients.is_empty()).then(|| clients.iter().map(String::as_str).collect())
    });
    for (id, seal) in &signing.seals {
        let id = id.as_str();
        let base = seal_pointer(id);
        if let Err(error) = runtime.secret_providers.check_reference(
            &format!("signing.seals.{id}.privateKeyRef"),
            &seal.private_key_ref,
        ) {
            findings.push(block_finding(&error));
        }
        if !is_plain_absolute(&seal.certificate_chain_file) {
            findings.push(finding(
                "render.runtime.relative-path",
                format!("{base}/certificateChainFile"),
                format!(
                    "signing.seals.{id}.certificateChainFile must be an absolute path to a file, \
                     with no `.` or `..` segment"
                ),
                "Write the absolute path of the PEM certificate chain file, the seal's own \
                 certificate first.",
            ));
        }
        match (&seal.timestamp_authority, &seal.without_timestamp) {
            (None, None) => findings.push(finding(
                "render.runtime.seal-timestamp-undecided",
                base.clone(),
                format!(
                    "signing.seals.{id} declares neither timestampAuthority nor withoutTimestamp; \
                     a seal without a timestamp stops validating when its certificate expires"
                ),
                "Declare timestampAuthority with the url of an RFC 3161 authority, or write \
                 withoutTimestamp: seal-stops-validating-when-certificate-expires to accept that \
                 consequence.",
            )),
            (Some(_), Some(_)) => findings.push(finding(
                "render.runtime.seal-timestamp-conflict",
                format!("{base}/withoutTimestamp"),
                format!("signing.seals.{id} declares both timestampAuthority and withoutTimestamp"),
                "Keep timestampAuthority to timestamp the seal, or withoutTimestamp to accept \
                 that the seal stops validating when its certificate expires; remove the other.",
            )),
            _ => {}
        }
        if let Some(authority) = &seal.timestamp_authority {
            if !registry_platform_httputil::client::transport_protects_the_credential(
                &authority.url.to_url(),
            ) {
                findings.push(finding(
                    "render.runtime.insecure-timestamp-url",
                    format!("{base}/timestampAuthority/url"),
                    format!(
                        "signing.seals.{id}.timestampAuthority.url must be an https URL; http is \
                         accepted only for a loopback host"
                    ),
                    "Use the https URL of the timestamp authority; use http only for a test \
                     authority on localhost.",
                ));
            }
        }
        let clients_pointer = format!("{base}/allowedClients");
        if !seal.allowed_clients.written_as_list || seal.allowed_clients.as_slice().is_empty() {
            findings.push(finding(
                "render.runtime.seal-clients-not-listed",
                clients_pointer.clone(),
                format!(
                    "signing.seals.{id}.allowedClients must list at least one client; a seal is \
                     never unrestricted and an empty list is not how a file says so, because a \
                     seal issues documents in the institution's name"
                ),
                "Name each OIDC client allowed to seal, for example [records-service]. Keep \
                 these separate from any citizen-facing client.",
            ));
        }
        for (index, client) in seal.allowed_clients.as_slice().iter().enumerate() {
            let pointer = format!("{clients_pointer}/{index}");
            if client == "unrestricted" || client.contains('*') {
                findings.push(finding(
                    "render.runtime.seal-client-wildcard",
                    pointer,
                    format!(
                        "signing.seals.{id}.allowedClients holds a wildcard or the unrestricted \
                         keyword as a client; a seal-capable client must be named"
                    ),
                    "Replace the item with the exact identifier of each client allowed to seal.",
                ));
            } else if admitted
                .as_ref()
                .is_some_and(|admitted| !admitted.contains(client.as_str()))
            {
                findings.push(finding(
                    "render.runtime.seal-client-not-admitted",
                    pointer,
                    format!(
                        "signing.seals.{id}.allowedClients names a client that \
                         authentication.oidc.allowedClients does not admit, so its token never reaches the \
                         seal"
                    ),
                    "Add the client to authentication.oidc.allowedClients, or remove it from the seal.",
                ));
            }
        }
    }
    findings
}

/// An absolute path to a file with no `.` or `..` segment.
fn is_plain_absolute(path: &Path) -> bool {
    use std::path::Component;
    path.is_absolute()
        && path.file_name().is_some()
        && path
            .to_str()
            .is_some_and(|text| !text.ends_with('/') && !text.contains("//"))
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

/// A finding of the bundle and runtime read together.
struct BindingFinding {
    severity: Severity,
    /// Placed at the mapping key at the pointer rather than at its value.
    at_key: bool,
    finding: Finding,
}

/// Resolve every seal id the bundle declares against `signing.seals`.
///
/// With no `signing` block sealing is off: a bundle that names seals is a
/// warning, so a development deployment without keys still serves while the
/// operator learns its sealed document types render unsealed. With one, a
/// document type that names a seal the runtime does not bind is an error,
/// and a runtime seal no document type names is a warning.
fn seal_binding_findings(runtime: &RenderRuntime, manifest: &Manifest) -> Vec<BindingFinding> {
    let Some(signing) = &runtime.signing else {
        let mut sealed: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for document in &manifest.documents {
            if let Some(seal) = document.seal.as_deref() {
                sealed.entry(seal).or_default().push(document.id.as_str());
            }
        }
        if sealed.is_empty() {
            return Vec::new();
        }
        let documents: Vec<&str> = sealed.values().flatten().copied().collect();
        let seals: Vec<String> = sealed.keys().map(|seal| format!("`{seal}`")).collect();
        return vec![BindingFinding {
            severity: Severity::Warning,
            at_key: false,
            finding: Finding {
                code: "render.runtime.seals-not-served",
                pointer: String::new(),
                message: format!(
                    "the bundle issues document type {} under seal {}; this runtime declares \
                     no signing block, so they render unsealed and the seal route is absent",
                    documents.join(", "),
                    seals.join(", ")
                ),
                action: "Declare signing.seals in the runtime file to seal them, or keep \
                         sealing off only where no sealed document is issued."
                    .to_owned(),
            },
        }];
    };
    let mut findings = Vec::new();
    let mut unbound: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut used = BTreeSet::new();
    for document in &manifest.documents {
        let Some(seal) = document.seal.as_deref() else {
            continue;
        };
        used.insert(seal);
        if runtime.seal(seal).is_none() {
            unbound.entry(seal).or_default().push(document.id.as_str());
        }
    }
    for (seal, documents) in unbound {
        findings.push(BindingFinding {
            severity: Severity::Error,
            at_key: false,
            finding: Finding {
                code: "render.runtime.seal-not-bound",
                pointer: "/signing/seals".to_owned(),
                message: format!(
                    "the bundle issues document type {} under seal `{seal}`, which \
                     signing.seals does not bind",
                    documents.join(", ")
                ),
                action: format!(
                    "Declare signing.seals.{seal} in the runtime file, or correct the `seal` \
                     member of the document type in manifest.yaml."
                ),
            },
        });
    }
    for id in signing.seals.keys() {
        if !used.contains(id.as_str()) {
            findings.push(BindingFinding {
                severity: Severity::Warning,
                at_key: true,
                finding: Finding {
                    code: "render.runtime.seal-unused",
                    pointer: seal_pointer(id.as_str()),
                    message: format!(
                        "signing.seals.{id} is bound to no document type of the bundle"
                    ),
                    action: "Name the seal in the `seal` member of a document type in \
                             manifest.yaml, or remove it from the runtime file."
                        .to_owned(),
                },
            });
        }
    }
    findings
}

/// Check the verified package's manifest against the runtime's seals before
/// serving: the same resolution `registry-render check` reports, without file
/// positions. An error is a document type whose seal the runtime does not
/// bind, refused as a runtime problem. With no `signing` block it accepts
/// every package, since sealing is then off. On success it returns the
/// warnings, such as a seal no document type uses or a bundle that names
/// seals served without a `signing` block.
pub fn validate_seal_bindings(
    runtime: &RenderRuntime,
    manifest: &Manifest,
) -> Result<Vec<Diagnostic>, RenderProblem> {
    let (mut errors, mut warnings) = (Vec::new(), Vec::new());
    for BindingFinding {
        severity, finding, ..
    } in seal_binding_findings(runtime, manifest)
    {
        let mut diagnostic = Diagnostic::error(
            finding.code,
            finding.pointer,
            finding.message,
            finding.action,
        );
        diagnostic.artifact = Some(RUNTIME_KIND.to_owned());
        diagnostic.severity = severity;
        if severity == Severity::Error {
            errors.push(diagnostic);
        } else {
            warnings.push(diagnostic);
        }
    }
    if errors.is_empty() {
        Ok(warnings)
    } else {
        errors.extend(warnings);
        Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            "the runtime configuration does not bind every seal the bundle names",
        )
        .with_diagnostics(errors))
    }
}

/// A value that satisfies the member at `pointer`, so a deferred expression
/// never decides whether its neighbours decode.
fn stand_in_for(pointer: &str) -> &'static str {
    match pointer {
        "/listener/bind" => "127.0.0.1:8080",
        "/package/root" => "/",
        "/package/expectedDigest" => {
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
        "/audit/destination" => "file",
        "/audit/path" => "/audit.jsonl",
        _ if pointer.starts_with("/signing/seals/")
            && pointer.ends_with("/timestampAuthority/url") =>
        {
            "https://stand-in.invalid/"
        }
        _ if pointer.starts_with("/signing/seals/")
            && pointer.ends_with("/certificateChainFile") =>
        {
            "/stand-in.pem"
        }
        _ => registry_platform_config::DEFAULT_STAND_IN,
    }
}

fn pointer_of(dotted: &str) -> String {
    dotted
        .split('.')
        .map(|segment| format!("/{}", escape_pointer_segment(segment)))
        .collect()
}

/// The code and fix for a shared package or secret provider refusal.
fn block_finding(error: &ConfigBlockError) -> Finding {
    let (code, action) = match error.kind() {
        ConfigBlockErrorKind::RelativePath => (
            "render.runtime.relative-path",
            "Write the path as an absolute path with no `.` or `..` segment.",
        ),
        ConfigBlockErrorKind::InvalidDigest => (
            "render.runtime.invalid-package-digest",
            "Write package.expectedDigest as the `sha256:` digest `registry-render package` \
             printed, or remove it.",
        ),
        ConfigBlockErrorKind::NoSecretProvider => (
            "render.runtime.no-secret-provider",
            "Declare secretProviders.file with an absolute root, \
             secretProviders.environment: {}, or both.",
        ),
        ConfigBlockErrorKind::InvalidSecretReference => (
            "render.runtime.invalid-secret-reference",
            "Write the reference as secret:file/<name> or secret:env/<NAME>.",
        ),
        ConfigBlockErrorKind::SecretProviderDisabled => (
            "render.runtime.undeclared-secret-provider",
            "Declare the provider the message names under secretProviders, or reference a \
             declared one.",
        ),
        _ => (
            "render.runtime.invalid-block",
            "Correct the member as the message describes.",
        ),
    };
    Finding {
        code,
        pointer: pointer_of(error.field()),
        message: error.to_string(),
        action: action.to_owned(),
    }
}

/// The code, position, and fix for a refusal of the audit block, under the
/// member names this file uses.
fn audit_finding(error: &AuditDestinationError) -> Finding {
    let finding = |code, pointer: &str, message: String, action: &str| Finding {
        code,
        pointer: pointer.to_owned(),
        message,
        action: action.to_owned(),
    };
    match error {
        AuditDestinationError::MissingPath => finding(
            "render.runtime.missing-audit-path",
            "/audit",
            error.to_string(),
            "Declare audit.path as the absolute path of the active audit file, or set \
             audit.destination to stdout.",
        ),
        AuditDestinationError::FileOnlyField { field } => {
            let member = match *field {
                "retainDays" => "retentionDays",
                other => other,
            };
            finding(
                "render.runtime.file-only-audit-member",
                &format!("/audit/{member}"),
                format!("audit.{member} applies only when audit.destination is file"),
                "Remove the member, or set audit.destination to file.",
            )
        }
        AuditDestinationError::RelativePath
        | AuditDestinationError::InvalidPathComponent
        | AuditDestinationError::NoFileName
        | AuditDestinationError::FileNameTooLong { .. } => finding(
            "render.runtime.invalid-audit-path",
            "/audit/path",
            error.to_string(),
            "Write audit.path as an absolute file path with no `.` or `..` segment, ending in \
             a file name.",
        ),
        AuditDestinationError::PathNamesReservedCompanion {
            suffix, companion, ..
        } => finding(
            "render.runtime.invalid-audit-path",
            "/audit/path",
            format!(
                "audit.path ends in `{suffix}`, which names the {companion} of another audit \
                 stream"
            ),
            "Choose an audit file name without that ending.",
        ),
        AuditDestinationError::RetainDaysOutOfRange { maximum } => finding(
            "render.runtime.invalid-audit",
            "/audit/retentionDays",
            format!("audit.retentionDays must be between 1 and {maximum}"),
            "Write a number of days within the bounds.",
        ),
        _ => finding(
            "render.runtime.invalid-audit",
            "/audit",
            error.to_string(),
            "Correct the audit block as the message describes.",
        ),
    }
}

/// Verify the shared package envelope, apply the optional digest pin, then
/// bind the exact captured product bytes that rendering will consume.
pub fn load_package(runtime: &RenderRuntime) -> Result<crate::Bundle, RenderProblem> {
    let verified = runtime
        .package
        .verify_package(&package_limits(), "registry-render package")
        .map_err(package_problem)?;
    crate::Bundle::load_package(&runtime.package.root, &verified)
}

/// Product bounds for authored and deployed Render packages.
pub fn package_limits() -> registry_platform_config::package::PackageLimits {
    registry_platform_config::package::PackageLimits::default()
}

pub(crate) fn package_problem(
    error: registry_platform_config::package::PackageError,
) -> RenderProblem {
    use registry_platform_config::package::PackageErrorKind;

    let kind = match error.kind() {
        PackageErrorKind::SumFileMissing => ProblemKind::PackageChecksumsMissing,
        PackageErrorKind::DigestMismatch(_) => ProblemKind::RuntimeInvalid,
        _ => ProblemKind::BundleTampered,
    };
    RenderProblem::new(kind, error.to_string())
}

fn invalid(message: impl Into<String>) -> RenderProblem {
    RenderProblem::new(ProblemKind::RuntimeInvalid, message)
}

/// Resolve a secret reference under the providers the runtime declares.
pub fn resolve_secret(runtime: &RenderRuntime, reference: &str) -> Result<Vec<u8>, RenderProblem> {
    let resolver = runtime
        .secret_providers
        .resolver()
        .map_err(|err| invalid(format!("secretProviders: {err}")))?;
    let secret = resolver
        .resolve(reference)
        .map_err(|err| invalid(format!("{err}")))?;
    Ok(secret.expose_secret().to_vec())
}

/// Resolve a secret reference into a buffer that is erased when dropped,
/// keeping the resolver's value-free reason for a refusal.
pub fn resolve_protected_secret(
    runtime: &RenderRuntime,
    reference: &str,
) -> Result<registry_platform_config::ProtectedSecret, registry_platform_config::SecretError> {
    runtime.secret_providers.resolver()?.resolve(reference)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// A canonical temporary directory: the loader refuses a path through a
    /// symbolic link, and the system temporary directory is one on some
    /// hosts.
    fn home() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("deployment home");
        let path = dir.path().canonicalize().expect("canonical home");
        (dir, path)
    }

    const HEAD: &str = "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1\nkind: RenderRuntimeConfig\n";

    fn minimal(home: &Path) -> String {
        format!(
            "{HEAD}listener:\n  bind: 127.0.0.1:8080\npackage:\n  root: /srv/render/package\nsecretProviders:\n  file:\n    root: {secrets}\nauthentication:\n  apiKeyRef: secret:file/api.key\naudit:\n  path: /var/lib/render/audit/render.jsonl\n",
            secrets = home.join("secrets").display(),
        )
    }

    fn load_text(home: &Path, text: &str) -> Result<RenderRuntime, RenderProblem> {
        let file = home.join("runtime.yaml");
        std::fs::write(&file, text).expect("runtime file");
        load(&file).map(|(runtime, _)| runtime)
    }

    /// The code and pointer of every finding of a refused file.
    fn codes(problem: &RenderProblem) -> Vec<(&str, &str)> {
        problem
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect()
    }

    fn refused(home: &Path, text: &str) -> RenderProblem {
        let problem = load_text(home, text).expect_err("the runtime file is refused");
        assert_eq!(problem.kind, ProblemKind::RuntimeInvalid);
        problem
    }

    #[cfg(unix)]
    fn assert_unsafe_runtime(problem: RenderProblem) {
        let diagnostic = problem
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "platform.runtime-config.unsafe-file")
            .expect("the ownership refusal is reported");
        assert!(diagnostic
            .message
            .contains("owned by root or the runtime user"));
        assert!(diagnostic
            .suggested_action
            .contains("remove group and other write permission"));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_loader_ownership_accepts_an_owner_writable_file_in_a_private_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_directory, home) = home();
        let path = home.join("runtime.yaml");
        std::fs::write(&path, minimal(&home)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        load(&path).expect("an owner-writable runtime in a private directory loads");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_loader_ownership_refuses_a_group_writable_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_directory, home) = home();
        let path = home.join("runtime.yaml");
        std::fs::write(&path, minimal(&home)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let result = load(&path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_unsafe_runtime(result.expect_err("a group-writable runtime is refused"));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_loader_ownership_refuses_a_group_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_directory, home) = home();
        let writable = home.join("writable");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o770)).unwrap();
        let path = writable.join("runtime.yaml");
        std::fs::write(&path, minimal(&home)).unwrap();
        let result = load(&path);
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_unsafe_runtime(
            result.expect_err("a runtime below a group-writable directory is refused"),
        );
    }

    #[test]
    fn the_runtime_configuration_is_read_through_the_shared_loader() {
        let (_dir, home) = home();
        let file = home.join("runtime.yaml");
        std::fs::write(&file, minimal(&home)).expect("runtime file");
        let (runtime, digest) = load(&file).expect("the minimal runtime loads");
        assert_eq!(runtime.listener.bind.socket_addr().port(), 8080);
        assert_eq!(runtime.package.root, PathBuf::from("/srv/render/package"));
        assert!(
            registry_platform_config::is_sha256_label(&digest),
            "{digest}"
        );

        let problem = refused(
            &home,
            &minimal(&home).replace(
                "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1",
                "apiVersion: render.registrystack.org/v1alpha1",
            ),
        );
        assert_eq!(
            codes(&problem),
            [("config.unsupported-api-version", "/apiVersion")]
        );
    }

    #[test]
    fn cfg_change_2_the_retired_api_version_names_every_rename() {
        let (_dir, home) = home();
        let problem = refused(
            &home,
            &minimal(&home).replace(
                "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1",
                "apiVersion: registry.registrystack.org/render-runtime/v1alpha1",
            ),
        );
        assert_eq!(
            codes(&problem),
            [("config.retired-api-version", "/apiVersion")]
        );
        let action = &problem.diagnostics[0].suggested_action;
        for rename in [
            "id.registrystack.org/formats/render/runtime/v1alpha1",
            "listener.shutdownGraceMilliseconds",
            "limits.maximumOutputBytes",
            "limits.maximumRequestBytes",
            "limits.maximumConcurrentRenders",
            "audit.retentionDays",
        ] {
            assert!(action.contains(rename), "{rename}: {action}");
        }
    }

    #[test]
    fn the_listener_bind_is_required() {
        let (_dir, home) = home();
        let text = minimal(&home).replace("listener:\n  bind: 127.0.0.1:8080\n", "");
        let problem = refused(&home, &text);
        assert_eq!(problem.diagnostics[0].code, "config.missing-key");
        assert!(
            problem.diagnostics[0].message.contains("listener"),
            "{:?}",
            problem.diagnostics
        );
    }

    #[test]
    fn cfg_change_2_removed_keys_name_their_replacements() {
        let (_dir, home) = home();
        let audit_path = "  path: /var/lib/render/audit/render.jsonl\n";
        for (text, pointer, replacement) in [
            (
                minimal(&home).replace("listener:\n  bind:", "server:\n  bind:"),
                "/server",
                "listener.bind",
            ),
            (
                minimal(&home).replace("package:\n  root:", "bundle:\n  path:"),
                "/bundle",
                "package.root",
            ),
            (
                minimal(&home).replace(
                    "  bind: 127.0.0.1:8080\n",
                    "  bind: 127.0.0.1:8080\n  shutdownGraceSeconds: 30\n",
                ),
                "/listener/shutdownGraceSeconds",
                "times 1000",
            ),
            (
                format!("{}limits:\n  maxOutputBytes: 1024\n", minimal(&home)),
                "/limits/maxOutputBytes",
                "limits.maximumOutputBytes",
            ),
            (
                format!("{}limits:\n  maxRequestBodyBytes: 1024\n", minimal(&home)),
                "/limits/maxRequestBodyBytes",
                "limits.maximumRequestBytes",
            ),
            (
                format!("{}limits:\n  maxConcurrency: 2\n", minimal(&home)),
                "/limits/maxConcurrency",
                "limits.maximumConcurrentRenders",
            ),
            (
                minimal(&home).replace(audit_path, "  directory: /var/lib/render/audit\n"),
                "/audit/directory",
                "audit.path",
            ),
            (
                minimal(&home).replace(
                    audit_path,
                    &format!("{audit_path}  integrityKeyRef: secret:file/audit.key\n"),
                ),
                "/audit/integrityKeyRef",
                "not hash-chained",
            ),
            (
                minimal(&home).replace(
                    audit_path,
                    &format!("{audit_path}  maxSegmentBytes: 67108864\n"),
                ),
                "/audit/maxSegmentBytes",
                "audit.rotateBytes",
            ),
            (
                minimal(&home).replace(audit_path, &format!("{audit_path}  retainDays: 30\n")),
                "/audit/retainDays",
                "audit.retentionDays",
            ),
            (
                minimal(&home).replace("authentication:\n", "auth:\n"),
                "/auth",
                "Rename `auth` to `authentication`",
            ),
        ] {
            let problem = refused(&home, &text);
            let removed = problem
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "config.removed-key")
                .unwrap_or_else(|| panic!("{pointer}: {:?}", problem.diagnostics));
            assert_eq!(removed.path, pointer);
            assert!(
                removed.suggested_action.contains(replacement),
                "{pointer}: {}",
                removed.suggested_action
            );
        }
    }

    #[test]
    fn package_and_audit_paths_must_be_absolute() {
        let (_dir, home) = home();
        for (text, expected) in [
            (
                minimal(&home).replace("root: /srv/render/package", "root: ../package"),
                ("render.runtime.relative-path", "/package/root"),
            ),
            (
                minimal(&home).replace(
                    "path: /var/lib/render/audit/render.jsonl",
                    "path: audit/render.jsonl",
                ),
                ("render.runtime.invalid-audit-path", "/audit/path"),
            ),
        ] {
            assert_eq!(codes(&refused(&home, &text)), [expected]);
        }
    }

    /// The runtime schema types `secretProviders.file` and `.environment` as
    /// a bare reference, so a null member is refused as a null.
    #[test]
    fn a_null_secret_provider_is_refused() {
        let (_dir, home) = home();
        for (member, pointer) in [
            ("file", "/secretProviders/file"),
            ("environment", "/secretProviders/environment"),
        ] {
            let text = minimal(&home).replace(
                &format!(
                    "secretProviders:\n  file:\n    root: {}\n",
                    home.join("secrets").display()
                ),
                &format!("secretProviders:\n  {member}:\n"),
            );
            let problem = refused(&home, &text);
            assert!(
                codes(&problem).contains(&("config.null-value", pointer)),
                "{member}: {:?}",
                codes(&problem)
            );
        }
    }

    #[test]
    fn a_secret_reference_must_name_a_declared_provider() {
        let (_dir, home) = home();
        let text = minimal(&home).replace(
            "apiKeyRef: secret:file/api.key",
            "apiKeyRef: secret:env/RENDER_API_KEY",
        );
        let problem = refused(&home, &text);
        assert_eq!(
            codes(&problem),
            [(
                "render.runtime.undeclared-secret-provider",
                "/authentication/apiKeyRef"
            )]
        );
        assert!(
            problem.diagnostics[0]
                .message
                .contains("secretProviders.environment"),
            "{}",
            problem.diagnostics[0].message
        );

        let text = text.replace(
            "secretProviders:\n",
            "secretProviders:\n  environment: {}\n",
        );
        load_text(&home, &text).expect("the declared environment provider admits the reference");

        let text = minimal(&home).replace(
            &format!(
                "secretProviders:\n  file:\n    root: {}\n",
                home.join("secrets").display()
            ),
            "secretProviders: {}\n",
        );
        let problem = refused(&home, &text);
        assert_eq!(
            codes(&problem),
            [
                ("render.runtime.no-secret-provider", "/secretProviders"),
                (
                    "render.runtime.undeclared-secret-provider",
                    "/authentication/apiKeyRef"
                ),
            ]
        );
    }

    #[test]
    fn environment_expressions_substitute_values_but_never_secret_references() {
        let (_dir, home) = home();
        let file = home.join("runtime.yaml");
        std::fs::write(
            &file,
            minimal(&home).replace(
                "root: /srv/render/package",
                "root: ${RENDER_PACKAGE_ROOT:-/srv/render/default}",
            ),
        )
        .expect("runtime file");
        let (runtime, _) = load(&file).expect("a defaulted expression loads");
        assert_eq!(runtime.package.root, PathBuf::from("/srv/render/default"));

        let text = minimal(&home).replace(
            "apiKeyRef: secret:file/api.key",
            "apiKeyRef: ${RENDER_API_KEY_REF:-secret:file/api.key}",
        );
        let problem = refused(&home, &text);
        assert_eq!(problem.diagnostics[0].path, "/authentication/apiKeyRef");
    }

    #[test]
    fn secrets_resolve_under_the_declared_file_root_only() {
        let (_dir, home) = home();
        let secrets = home.join("secrets");
        std::fs::create_dir_all(&secrets).expect("secret root");
        write_secret(&secrets.join("api.key"), b"from-the-declared-root");
        // A file beside the runtime file is not a secret root.
        write_secret(&home.join("audit.key"), b"beside-the-runtime-file");
        let runtime = load_text(&home, &minimal(&home)).expect("runtime loads");
        assert_eq!(
            resolve_secret(
                &runtime,
                runtime
                    .authentication
                    .api_key_ref
                    .as_deref()
                    .expect("key mode")
            )
            .expect("declared root"),
            b"from-the-declared-root"
        );
        resolve_secret(&runtime, "secret:file/audit.key")
            .expect_err("a file outside the declared root does not resolve");
    }

    fn with_audit(home: &Path, audit: &str) -> String {
        minimal(home).replace("  path: /var/lib/render/audit/render.jsonl\n", audit)
    }

    #[test]
    fn the_audit_block_takes_the_shared_destination_shape() {
        let (_dir, home) = home();
        let file = load_text(
            &home,
            &with_audit(
                &home,
                "  path: /a/render.jsonl\n  rotateBytes: 1048576\n  retentionDays: 30\n",
            ),
        )
        .expect("a file destination with rotation and retention loads");
        match file.audit.destination().expect("destination") {
            AuditDestination::File(file) => {
                assert_eq!(file.path(), Path::new("/a/render.jsonl"));
                assert_eq!(file.rotate_bytes(), 1_048_576);
                assert_eq!(file.retain_days(), 30);
            }
            AuditDestination::Stdout | AuditDestination::Stderr => {
                panic!("file is the default destination")
            }
        }
        let stdout = load_text(&home, &with_audit(&home, "  destination: stdout\n"))
            .expect("a stdout destination loads");
        assert_eq!(
            stdout.audit.destination().expect("destination"),
            AuditDestination::Stdout
        );
    }

    #[test]
    fn an_audit_block_outside_the_shared_shape_is_refused() {
        let (_dir, home) = home();
        for (audit, code, pointer) in [
            (
                "  destination: file\n",
                "render.runtime.missing-audit-path",
                "/audit",
            ),
            (
                "  path: \"\"\n",
                "render.runtime.invalid-audit-path",
                "/audit/path",
            ),
            (
                "  destination: stdout\n  path: /a/render.jsonl\n",
                "render.runtime.file-only-audit-member",
                "/audit/path",
            ),
            (
                "  destination: stdout\n  retentionDays: 7\n",
                "render.runtime.file-only-audit-member",
                "/audit/retentionDays",
            ),
            (
                "  path: /a/render.jsonl\n  rotateBytes: 1024\n",
                "config.out-of-range",
                "/audit/rotateBytes",
            ),
            (
                "  path: /a/render.jsonl\n  retentionDays: 0\n",
                "config.out-of-range",
                "/audit/retentionDays",
            ),
            (
                "  path: /a/render.jsonl\n  retentionDays: 36501\n",
                "config.out-of-range",
                "/audit/retentionDays",
            ),
            (
                "  path: /a/../render.jsonl\n",
                "render.runtime.invalid-audit-path",
                "/audit/path",
            ),
        ] {
            let problem = refused(&home, &with_audit(&home, audit));
            assert_eq!(codes(&problem), [(code, pointer)], "{audit}");
        }
        // The message names the member as this file spells it.
        let problem = refused(
            &home,
            &with_audit(&home, "  destination: stdout\n  retentionDays: 7\n"),
        );
        assert_eq!(
            problem.diagnostics[0].message,
            "audit.retentionDays applies only when audit.destination is file"
        );
    }

    fn write_secret(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, bytes).expect("secret file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("secret mode");
    }

    #[test]
    fn container_private_exposure_is_explicit_and_still_refuses_public_addresses() {
        let (_dir, home) = home();
        let text = minimal(&home).replace(
            "bind: 127.0.0.1:8080",
            "bind: 0.0.0.0:8080\n  networkExposure: container-private",
        );
        assert!(
            load_text(&home, &text).is_ok(),
            "container-private wildcard must load"
        );
        let public = text.replace("0.0.0.0:8080", "203.0.113.9:8080");
        assert!(
            load_text(&home, &public).is_err(),
            "public address stays refused"
        );
    }

    #[test]
    fn oidc_is_an_explicit_alternative_to_the_legacy_key() {
        let (_dir, home) = home();
        let oidc = "oidc:\n    issuer: https://issuer.example.test\n    audience: https://render.example.test\n    allowedClients: [portal]";
        let text = minimal(&home).replace("apiKeyRef: secret:file/api.key", oidc);
        assert!(
            load_text(&home, &text).is_ok(),
            "OIDC runtime loads without caller API key"
        );
        let both = text.replace(
            "authentication:\n",
            "authentication:\n  apiKeyRef: secret:file/api.key\n",
        );
        assert!(
            load_text(&home, &both).is_err(),
            "no ambiguous authentication fallback"
        );
        assert!(load_text(
            &home,
            &minimal(&home).replace("apiKeyRef: secret:file/api.key", "{}")
        )
        .is_err());
    }

    #[test]
    fn oidc_optional_auth_members_refuse_explicit_null_and_validate_declared_providers() {
        let (_dir, home) = home();
        let oidc = "oidc:\n    issuer: https://issuer.example.test\n    audience: https://render.example.test\n    allowedClients: [portal]";
        let text = minimal(&home).replace("apiKeyRef: secret:file/api.key", oidc);
        assert!(load_text(&home, &text).is_ok());
        for extra in ["  apiKeyRef: null\n", "  oidc: null\n"] {
            let base = if extra.contains("oidc") {
                minimal(&home)
            } else {
                text.clone()
            };
            assert!(
                load_text(
                    &home,
                    &base.replace("authentication:\n", &format!("authentication:\n{extra}"))
                )
                .is_err(),
                "explicit null: {extra}"
            );
        }
        let relative = text.replace(
            &format!("root: {}", home.join("secrets").display()),
            "root: relative-secrets",
        );
        assert_ne!(
            relative, text,
            "fixture must replace the declared file root"
        );
        assert!(
            load_text(&home, &relative).is_err(),
            "unused declared provider is still validated"
        );
    }

    #[test]
    fn loopback_private_and_link_local_binds_are_allowed() {
        for bind in [
            "127.0.0.1:8080",
            "10.0.0.5:8080",
            "192.168.1.10:8080",
            "172.16.0.1:8080",
            "169.254.7.7:8080",
            "[::1]:8080",
            "[fe80::1]:8080",
            "[fd00::5]:8080",
        ] {
            let addr: SocketAddr = bind.parse().unwrap();
            validate_bind(addr).unwrap_or_else(|err| panic!("{bind} must be allowed: {err}"));
        }
    }

    #[test]
    fn a_public_bind_in_the_file_is_refused_at_its_value() {
        let (_dir, home) = home();
        let problem = refused(
            &home,
            &minimal(&home).replace("bind: 127.0.0.1:8080", "bind: 0.0.0.0:8080"),
        );
        assert_eq!(
            codes(&problem),
            [("render.runtime.public-bind", "/listener/bind")]
        );
        let diagnostic = &problem.diagnostics[0];
        let source = diagnostic.source.as_ref().expect("positioned");
        assert_eq!((source.line, source.column), (Some(4), Some(9)));
        // CFG-SEC-3: the finding names the member, never its value.
        assert!(
            !diagnostic.message.contains("0.0.0.0"),
            "{}",
            diagnostic.message
        );
    }

    #[test]
    fn cfg_qty_4_shutdown_grace_outside_its_bounds_is_refused() {
        // A grace under a second drops renders in flight on SIGTERM, and a
        // grace past the hour overflows the bounded wait the shutdown path
        // computes.
        let (_dir, home) = home();
        for grace in ["0", "999", "3600001", "10000000000000000000"] {
            let text = minimal(&home).replace(
                "  bind: 127.0.0.1:8080\n",
                &format!("  bind: 127.0.0.1:8080\n  shutdownGraceMilliseconds: {grace}\n"),
            );
            assert_eq!(
                codes(&refused(&home, &text)),
                [("config.out-of-range", "/listener/shutdownGraceMilliseconds")],
                "grace {grace}"
            );
        }
    }

    #[test]
    fn shutdown_grace_at_the_range_ends_is_accepted() {
        let (_dir, home) = home();
        for grace in [1_000, 3_600_000] {
            let text = minimal(&home).replace(
                "  bind: 127.0.0.1:8080\n",
                &format!("  bind: 127.0.0.1:8080\n  shutdownGraceMilliseconds: {grace}\n"),
            );
            let runtime = load_text(&home, &text).expect("grace at the range end loads");
            assert_eq!(
                runtime.listener.shutdown_grace(),
                Duration::from_millis(grace)
            );
        }
        let runtime = load_text(&home, &minimal(&home)).expect("runtime loads");
        assert_eq!(runtime.listener.shutdown_grace(), Duration::from_secs(30));
    }

    #[test]
    fn cfg_qty_4_every_limit_is_bounded() {
        let (_dir, home) = home();
        for (limit, value) in [
            ("renderTimeoutSeconds", "0"),
            ("renderTimeoutSeconds", "3601"),
            ("maximumOutputBytes", "0"),
            ("maximumOutputBytes", "8388609"),
            ("maximumRequestBytes", "0"),
            ("maximumRequestBytes", "67108865"),
            ("maximumConcurrentRenders", "0"),
            ("maximumConcurrentRenders", "65"),
        ] {
            let text = format!("{}limits:\n  {limit}: {value}\n", minimal(&home));
            let pointer = format!("/limits/{limit}");
            assert_eq!(
                codes(&refused(&home, &text)),
                [("config.out-of-range", pointer.as_str())],
                "{limit} {value}"
            );
        }
        let text = format!(
            "{}limits:\n  renderTimeoutSeconds: 3600\n  maximumOutputBytes: 8388608\n  maximumRequestBytes: 67108864\n  maximumConcurrentRenders: 64\n",
            minimal(&home)
        );
        let limits = load_text(&home, &text)
            .expect("limits at their maximum load")
            .limits;
        assert_eq!(limits.render_timeout(), Duration::from_secs(3600));
        assert_eq!(limits.output_bytes(), 8 * 1024 * 1024);
        assert_eq!(limits.request_bytes(), 64 * 1024 * 1024);
        assert_eq!(limits.concurrent_renders(), 64);
    }

    #[test]
    fn omitted_limits_take_their_defaults() {
        let (_dir, home) = home();
        let limits = load_text(&home, &minimal(&home))
            .expect("runtime loads")
            .limits;
        assert_eq!(limits.render_timeout(), Duration::from_secs(20));
        assert_eq!(
            limits.output_bytes(),
            crate::render::DEFAULT_MAX_OUTPUT_BYTES
        );
        assert_eq!(limits.request_bytes(), 8 * 1024 * 1024);
        assert!((1..=8).contains(&limits.concurrent_renders()));
    }

    #[test]
    fn cfg_diag_5_every_finding_is_reported_in_one_run() {
        let (_dir, home) = home();
        let text = minimal(&home)
            .replace("bind: 127.0.0.1:8080", "bind: 0.0.0.0:8080")
            .replace("root: /srv/render/package", "root: package")
            .replace(
                "apiKeyRef: secret:file/api.key",
                "apiKeyRef: secret:env/KEY",
            )
            .replace(
                "  path: /var/lib/render/audit/render.jsonl\n",
                "  destination: file\n",
            );
        let problem = refused(&home, &text);
        assert_eq!(
            codes(&problem),
            [
                ("render.runtime.public-bind", "/listener/bind"),
                ("render.runtime.relative-path", "/package/root"),
                (
                    "render.runtime.undeclared-secret-provider",
                    "/authentication/apiKeyRef"
                ),
                ("render.runtime.missing-audit-path", "/audit"),
            ]
        );
        // Serve prints the same lines on standard error (CFG-DIAG-2).
        let human = problem.render_human();
        let file = home.join("runtime.yaml");
        assert!(
            human.starts_with(
                "registry-render: runtime-invalid: the runtime configuration was refused\n"
            ),
            "{human}"
        );
        assert!(
            human.contains(&format!(
                "error[render.runtime.public-bind] {}:4:9 /listener/bind\n",
                file.display()
            )),
            "{human}"
        );
        assert!(
            human.ends_with("4 errors, 0 warnings in 1 file\n"),
            "{human}"
        );
    }

    #[test]
    fn cfg_check_1_an_expression_is_checked_by_position_without_the_environment() {
        let (_dir, home) = home();
        let file = home.join("runtime.yaml");
        std::fs::write(
            &file,
            minimal(&home)
                .replace("127.0.0.1:8080", "\"${RENDER_CHECK_UNSET_BIND}\"")
                .replace(
                    "/var/lib/render/audit/render.jsonl",
                    "${RENDER_CHECK_UNSET_AUDIT}",
                ),
        )
        .expect("runtime file");
        let offline = check_runtime(&file, false, None);
        assert!(offline.diagnostics.is_empty(), "{:?}", offline.diagnostics);
        assert!(!offline.unavailable);

        // Substituting from the environment checks the values, and an unset
        // variable is reported where it is written.
        let substituted = check_runtime(&file, true, None);
        assert_eq!(
            substituted
                .diagnostics
                .first()
                .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str())),
            Some(("config.substitution", "/listener/bind"))
        );
    }

    #[test]
    fn cfg_check_1_an_unreadable_file_is_an_operational_failure() {
        let (_dir, home) = home();
        let check = check_runtime(&home.join("missing.yaml"), false, None);
        assert!(check.unavailable);
        assert_eq!(check.diagnostics.len(), 1);

        let problem = load(&home.join("missing.yaml")).expect_err("no file");
        assert_eq!(
            problem.detail,
            "the runtime configuration could not be read"
        );
    }

    const SEAL: &str = "    ministry:\n      privateKeyRef: secret:file/seal.jwk\n      certificateChainFile: /etc/render/seal/chain.pem\n      timestampAuthority:\n        url: https://tsa.example.test/tsr\n      allowedClients: [records-service]\n";

    /// OIDC authentication admitting `portal` and `records-service`, then a
    /// `signing` block holding `seals` (the indented body under `seals:`).
    fn signing_text(home: &Path, seals: &str) -> String {
        let oidc = "oidc:\n    issuer: https://issuer.example.test\n    audience: https://render.example.test\n    allowedClients: [portal, records-service]";
        format!(
            "{}signing:\n  seals:\n{seals}",
            minimal(home).replace("apiKeyRef: secret:file/api.key", oidc)
        )
    }

    fn signing_manifest(documents: &[(&str, Option<&str>)]) -> Manifest {
        let mut text = String::from(
            "apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n",
        );
        for (id, seal) in documents {
            text.push_str(&format!(
                "  - id: {id}\n    version: 1\n    entryFile: templates/{id}.typ\n"
            ));
            if let Some(seal) = seal {
                text.push_str(&format!("    seal: {seal}\n"));
            }
        }
        Manifest::parse(text.as_bytes()).expect("the manifest parses")
    }

    #[test]
    fn a_signing_block_loads_with_its_defaults_and_accessors() {
        let (_dir, home) = home();
        let runtime = load_text(&home, &signing_text(&home, SEAL)).expect("signing loads");
        let seal = runtime.seal("ministry").expect("the seal is bound");
        assert_eq!(seal.private_key_ref, "secret:file/seal.jwk");
        assert_eq!(
            seal.certificate_chain_file,
            PathBuf::from("/etc/render/seal/chain.pem")
        );
        let authority = seal.timestamp_authority.as_ref().expect("timestamps");
        assert_eq!(authority.attempt_timeout(), Duration::from_secs(10));
        assert!(seal.without_timestamp.is_none());
        assert!(seal.allows_client("records-service"));
        assert!(!seal.allows_client("portal"));
        assert!(!seal.is_test_only());
        assert!(runtime.seal("other").is_none());

        let text = signing_text(&home, SEAL).replace(
            "      allowedClients: [records-service]\n",
            "      allowedClients: [records-service]\n      trust: test-only\n",
        );
        let runtime = load_text(&home, &text).expect("a test-only seal loads");
        assert!(runtime.seal("ministry").unwrap().is_test_only());
    }

    #[test]
    fn without_a_signing_block_sealing_is_off() {
        let (_dir, home) = home();
        let runtime = load_text(&home, &minimal(&home)).expect("runtime loads");
        assert!(runtime.signing.is_none());
        assert!(runtime.seal("ministry").is_none());
        let manifest = signing_manifest(&[("licence", Some("ministry"))]);
        assert!(runtime.seal_for(&manifest, "licence").is_none());
        let warnings = validate_seal_bindings(&runtime, &manifest)
            .expect("a package that names a seal still serves with sealing off");
        assert_eq!(
            warnings.len(),
            1,
            "it says the sealed type renders unsealed"
        );
    }

    #[test]
    fn signing_block_refusals_are_placed_at_the_offending_member() {
        let (_dir, home) = home();
        let ts_url = "        url: https://tsa.example.test/tsr\n";
        let clients = "      allowedClients: [records-service]\n";
        let cases: Vec<(String, &str, &str)> = vec![
            (
                SEAL.replace("secret:file/seal.jwk", "secret:env/SEAL_KEY"),
                "render.runtime.undeclared-secret-provider",
                "/signing/seals/ministry/privateKeyRef",
            ),
            (
                SEAL.replace("secret:file/seal.jwk", "/etc/render/seal.jwk"),
                "render.runtime.invalid-secret-reference",
                "/signing/seals/ministry/privateKeyRef",
            ),
            (
                SEAL.replace("/etc/render/seal/chain.pem", "chain.pem"),
                "render.runtime.relative-path",
                "/signing/seals/ministry/certificateChainFile",
            ),
            (
                SEAL.replace("/etc/render/seal/chain.pem", "/etc/render/../chain.pem"),
                "render.runtime.relative-path",
                "/signing/seals/ministry/certificateChainFile",
            ),
            (
                SEAL.replace(
                    "      timestampAuthority:\n        url: https://tsa.example.test/tsr\n",
                    "",
                ),
                "render.runtime.seal-timestamp-undecided",
                "/signing/seals/ministry",
            ),
            (
                SEAL.replace(
                    ts_url,
                    &format!("{ts_url}      withoutTimestamp: seal-stops-validating-when-certificate-expires\n"),
                ),
                "render.runtime.seal-timestamp-conflict",
                "/signing/seals/ministry/withoutTimestamp",
            ),
            (
                SEAL.replace("https://tsa", "http://tsa"),
                "render.runtime.insecure-timestamp-url",
                "/signing/seals/ministry/timestampAuthority/url",
            ),
            (
                SEAL.replace(ts_url, &format!("{ts_url}        attemptTimeoutMilliseconds: 999\n")),
                "config.out-of-range",
                "/signing/seals/ministry/timestampAuthority/attemptTimeoutMilliseconds",
            ),
            (
                SEAL.replace(ts_url, &format!("{ts_url}        attemptTimeoutMilliseconds: 60001\n")),
                "config.out-of-range",
                "/signing/seals/ministry/timestampAuthority/attemptTimeoutMilliseconds",
            ),
            (
                SEAL.replace(clients, "      allowedClients: unrestricted\n"),
                "render.runtime.seal-clients-not-listed",
                "/signing/seals/ministry/allowedClients",
            ),
            (
                SEAL.replace(clients, "      allowedClients: records-service\n"),
                "render.runtime.seal-clients-not-listed",
                "/signing/seals/ministry/allowedClients",
            ),
            (
                SEAL.replace(clients, "      allowedClients: []\n"),
                "render.runtime.seal-clients-not-listed",
                "/signing/seals/ministry/allowedClients",
            ),
            (
                SEAL.replace(clients, "      allowedClients: ['*']\n"),
                "render.runtime.seal-client-wildcard",
                "/signing/seals/ministry/allowedClients/0",
            ),
            (
                SEAL.replace(clients, "      allowedClients: [records-service, unrestricted]\n"),
                "render.runtime.seal-client-wildcard",
                "/signing/seals/ministry/allowedClients/1",
            ),
            (
                SEAL.replace(clients, "      allowedClients: ['records-*']\n"),
                "render.runtime.seal-client-wildcard",
                "/signing/seals/ministry/allowedClients/0",
            ),
            (
                SEAL.replace(clients, "      allowedClients: [records-service, batch-job]\n"),
                "render.runtime.seal-client-not-admitted",
                "/signing/seals/ministry/allowedClients/1",
            ),
            (
                SEAL.replace(clients, "      allowedClients: [records-service, records-service]\n"),
                "config.duplicate-item",
                "/signing/seals/ministry/allowedClients/1",
            ),
            (
                SEAL.replace(clients, ""),
                "config.missing-key",
                "/signing/seals/ministry",
            ),
            (
                SEAL.replace(clients, &format!("{clients}      keyFile: /etc/seal.jwk\n")),
                "config.unknown-key",
                "/signing/seals/ministry/keyFile",
            ),
            (
                SEAL.replace(clients, &format!("{clients}      trust: production\n")),
                "config.unknown-variant",
                "/signing/seals/ministry/trust",
            ),
            (
                SEAL.replace(ts_url, &format!("{ts_url}        retries: 3\n")),
                "config.unknown-key",
                "/signing/seals/ministry/timestampAuthority/retries",
            ),
        ];
        for (seal, code, pointer) in cases {
            let problem = refused(&home, &signing_text(&home, &seal));
            assert!(
                codes(&problem).contains(&(code, pointer)),
                "{code} {pointer}: {:?}\n{seal}",
                codes(&problem)
            );
        }
    }

    #[test]
    fn loopback_http_is_accepted_for_a_test_timestamp_authority() {
        let (_dir, home) = home();
        for url in [
            "http://localhost:3161/tsr",
            "http://LOCALHOST:3161/tsr",
            "http://127.0.0.1:3161/tsr",
            "http://127.0.0.2:3161/tsr",
            "http://[::1]:3161/tsr",
            "https://tsa.example.test/tsr",
        ] {
            let seal = SEAL.replace("https://tsa.example.test/tsr", url);
            load_text(&home, &signing_text(&home, &seal)).unwrap_or_else(|problem| {
                panic!("{url}: {:?}", codes(&problem));
            });
        }
        for url in [
            "http://tsa.example.test/tsr",
            "http://10.0.0.5/tsr",
            "http://localhost.example.test/",
            "http://localhost./tsr",
            "http://[::ffff:127.0.0.1]/tsr",
        ] {
            let seal = SEAL.replace("https://tsa.example.test/tsr", url);
            let problem = refused(&home, &signing_text(&home, &seal));
            assert_eq!(
                codes(&problem),
                [(
                    "render.runtime.insecure-timestamp-url",
                    "/signing/seals/ministry/timestampAuthority/url"
                )],
                "{url}"
            );
        }
    }

    #[test]
    fn the_timestamp_attempt_is_bounded_and_the_named_value_goes_without_a_timestamp() {
        let (_dir, home) = home();
        for ms in [1_000, 60_000] {
            let seal = SEAL.replace(
                "https://tsa.example.test/tsr\n",
                &format!(
                    "https://tsa.example.test/tsr\n        attemptTimeoutMilliseconds: {ms}\n"
                ),
            );
            let runtime = load_text(&home, &signing_text(&home, &seal)).expect("bound accepted");
            let authority = runtime
                .seal("ministry")
                .unwrap()
                .timestamp_authority
                .clone()
                .unwrap();
            assert_eq!(authority.attempt_timeout(), Duration::from_millis(ms));
        }
        let without = SEAL.replace(
            "      timestampAuthority:\n        url: https://tsa.example.test/tsr\n",
            "      withoutTimestamp: seal-stops-validating-when-certificate-expires\n",
        );
        let runtime = load_text(&home, &signing_text(&home, &without)).expect("B-B is allowed");
        let seal = runtime.seal("ministry").unwrap();
        assert!(seal.timestamp_authority.is_none());
        assert_eq!(
            seal.without_timestamp,
            Some(WithoutTimestamp::SealStopsValidatingWhenCertificateExpires)
        );
        // A boolean or any other value is not the named acknowledgement.
        for value in ["true", "without-timestamp", "yes"] {
            let seal = without.replace("seal-stops-validating-when-certificate-expires", value);
            let problem = refused(&home, &signing_text(&home, &seal));
            assert!(
                problem
                    .diagnostics
                    .iter()
                    .any(|d| d.path == "/signing/seals/ministry/withoutTimestamp"),
                "{value}: {:?}",
                codes(&problem)
            );
        }
    }

    #[test]
    fn the_unrestricted_refusal_states_why_and_never_repeats_a_client() {
        let (_dir, home) = home();
        let seal = SEAL.replace("[records-service]", "[records-service, 'batch-*']");
        let problem = refused(&home, &signing_text(&home, &seal));
        let diagnostic = &problem.diagnostics[0];
        assert_eq!(diagnostic.code, "render.runtime.seal-client-wildcard");
        assert!(
            diagnostic.message.contains("must be named"),
            "{}",
            diagnostic.message
        );
        assert!(
            !diagnostic.message.contains("batch-"),
            "{}",
            diagnostic.message
        );
        let source = diagnostic.source.as_ref().expect("positioned");
        assert!(source.line.is_some() && source.column.is_some());

        let problem = refused(
            &home,
            &signing_text(&home, &SEAL.replace("[records-service]", "unrestricted")),
        );
        assert!(
            problem.diagnostics[0]
                .message
                .contains("never unrestricted"),
            "{}",
            problem.diagnostics[0].message
        );
    }

    #[test]
    fn a_seal_may_use_any_client_when_oidc_admits_every_client() {
        let (_dir, home) = home();
        let text = signing_text(&home, SEAL).replace(
            "allowedClients: [portal, records-service]",
            "allowedClients: unrestricted",
        );
        load_text(&home, &text).expect("the seal narrows an unrestricted issuer");
    }

    #[test]
    fn signing_needs_oidc_and_refuses_the_legacy_key() {
        let (_dir, home) = home();
        let text = format!("{}signing:\n  seals:\n{SEAL}", minimal(&home));
        let problem = refused(&home, &text);
        assert_eq!(
            codes(&problem)
                .into_iter()
                .filter(|(code, _)| code.starts_with("render.runtime.signing"))
                .collect::<Vec<_>>(),
            [("render.runtime.signing-requires-oidc", "/signing")]
        );
        let action = problem
            .diagnostics
            .iter()
            .find(|d| d.code == "render.runtime.signing-requires-oidc")
            .map(|d| d.suggested_action.as_str())
            .unwrap();
        assert!(action.contains("authentication.oidc"), "{action}");
    }

    #[test]
    fn a_signing_block_with_no_seal_or_a_null_is_refused() {
        let (_dir, home) = home();
        let oidc = "oidc:\n    issuer: https://issuer.example.test\n    audience: https://render.example.test\n    allowedClients: [portal]";
        let base = minimal(&home).replace("apiKeyRef: secret:file/api.key", oidc);
        let problem = refused(&home, &format!("{base}signing:\n  seals: {{}}\n"));
        assert!(codes(&problem).contains(&("render.runtime.no-seals", "/signing/seals")));
        let problem = refused(&home, &format!("{base}signing:\n"));
        assert!(
            codes(&problem).contains(&("config.null-value", "/signing")),
            "{:?}",
            codes(&problem)
        );
        let problem = refused(
            &home,
            &format!(
                "{base}signing:\n  seals:\n    Ministry:\n{}",
                SEAL.replace("    ministry:\n", "")
            ),
        );
        assert!(!problem.diagnostics.is_empty());
    }

    #[test]
    fn the_secret_reference_uses_the_declared_provider() {
        let (_dir, home) = home();
        let text = signing_text(
            &home,
            &SEAL.replace("secret:file/seal.jwk", "secret:env/SEAL_KEY"),
        )
        .replace(
            "secretProviders:\n",
            "secretProviders:\n  environment: {}\n",
        );
        load_text(&home, &text).expect("a declared environment provider admits the reference");
    }

    #[test]
    fn a_bundle_seal_the_runtime_does_not_bind_is_refused_when_signing_is_configured() {
        let (_dir, home) = home();
        let file = home.join("runtime.yaml");
        std::fs::write(&file, signing_text(&home, SEAL)).unwrap();
        let manifest = signing_manifest(&[
            ("licence", Some("ministry")),
            ("permit", Some("regional")),
            ("receipt", Some("regional")),
            ("notice", None),
        ]);
        let check = check_runtime_with_bundle(&file, false, None, Some(&manifest));
        assert!(!check.unavailable);
        assert_eq!(check.diagnostics.len(), 1, "{:?}", check.diagnostics);
        let diagnostic = &check.diagnostics[0];
        assert_eq!(diagnostic.code, "render.runtime.seal-not-bound");
        assert_eq!(diagnostic.path, "/signing/seals");
        assert_eq!(diagnostic.severity, Severity::Error);
        assert!(
            diagnostic.message.contains("permit, receipt"),
            "{}",
            diagnostic.message
        );
        let source = diagnostic.source.as_ref().expect("positioned");
        assert_eq!(source.file, file.display().to_string());
        // The mapping of seals starts at its first seal.
        let text = std::fs::read_to_string(&file).unwrap();
        let first_seal = text.lines().position(|l| l == "    ministry:").unwrap() + 1;
        assert_eq!(source.line, Some(first_seal));

        let runtime = load_text(&home, &signing_text(&home, SEAL)).unwrap();
        let problem = validate_seal_bindings(&runtime, &manifest).expect_err("unbound seal");
        assert_eq!(problem.kind, ProblemKind::RuntimeInvalid);
        assert_eq!(problem.diagnostics[0].code, "render.runtime.seal-not-bound");
    }

    #[test]
    fn a_package_serves_without_a_signing_block_even_when_it_names_seals() {
        let (_dir, home) = home();
        let file = home.join("runtime.yaml");
        std::fs::write(&file, minimal(&home)).unwrap();
        let manifest = signing_manifest(&[
            ("licence", Some("ministry")),
            ("permit", Some("regional")),
            ("notice", None),
        ]);
        let check = check_runtime_with_bundle(&file, false, None, Some(&manifest));
        assert_eq!(check.diagnostics.len(), 1, "{:?}", check.diagnostics);
        let warning = &check.diagnostics[0];
        assert_eq!(warning.code, "render.runtime.seals-not-served");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.path, "");
        assert!(
            warning.message.contains("licence, permit") && warning.message.contains("unsealed"),
            "{}",
            warning.message
        );
        assert!(warning.source.is_some(), "placed in the runtime file");

        // serve starts and logs it: a development deployment needs no keys.
        let runtime = load_text(&home, &minimal(&home)).unwrap();
        let warnings = validate_seal_bindings(&runtime, &manifest).expect("a warning serves");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "render.runtime.seals-not-served");

        let unsealed = signing_manifest(&[("notice", None)]);
        let check = check_runtime_with_bundle(&file, false, None, Some(&unsealed));
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
    }

    #[test]
    fn a_runtime_seal_no_document_uses_is_a_warning_that_does_not_refuse() {
        let (_dir, home) = home();
        let file = home.join("runtime.yaml");
        let text = signing_text(
            &home,
            &format!("{SEAL}{}", SEAL.replace("ministry", "spare")),
        );
        std::fs::write(&file, &text).unwrap();
        let manifest = signing_manifest(&[("licence", Some("ministry")), ("notice", None)]);
        let check = check_runtime_with_bundle(&file, false, None, Some(&manifest));
        assert_eq!(check.diagnostics.len(), 1, "{:?}", check.diagnostics);
        let warning = &check.diagnostics[0];
        assert_eq!(warning.code, "render.runtime.seal-unused");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.path, "/signing/seals/spare");
        let source = warning.source.as_ref().expect("positioned");
        assert_eq!(source.column, Some(5), "placed at the key of the seal");

        let runtime = load_text(&home, &text).unwrap();
        let warnings = validate_seal_bindings(&runtime, &manifest).expect("a warning serves");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].severity, Severity::Warning);
    }

    #[test]
    fn seal_for_resolves_the_bundle_declaration_through_the_runtime() {
        let (_dir, home) = home();
        let runtime = load_text(&home, &signing_text(&home, SEAL)).unwrap();
        let manifest = signing_manifest(&[("licence", Some("ministry")), ("notice", None)]);
        assert!(runtime.seal_for(&manifest, "licence").is_some());
        assert!(runtime.seal_for(&manifest, "notice").is_none());
        assert!(runtime.seal_for(&manifest, "absent").is_none());
        let regional = signing_manifest(&[("permit", Some("regional"))]);
        assert!(runtime.seal_for(&regional, "permit").is_none());
    }

    #[test]
    fn public_and_unspecified_binds_are_refused() {
        for bind in [
            "0.0.0.0:8080",
            "8.8.8.8:8080",
            "203.0.113.9:8080",
            "[::]:8080",
            "[2001:db8::1]:8080",
        ] {
            let addr: SocketAddr = bind.parse().unwrap();
            let problem = validate_bind(addr).expect_err(bind);
            assert_eq!(problem.kind, ProblemKind::RuntimeInvalid, "{bind}");
            assert!(
                problem.detail.contains("listener.bind"),
                "{}",
                problem.detail
            );
        }
    }
}
