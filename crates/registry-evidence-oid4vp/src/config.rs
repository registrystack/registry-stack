//! Startup-only configuration for the wallet protocol service.
//!
//! The document is read whole through the shared runtime reader and validated
//! whole, so a deployment either starts on a coherent configuration or does
//! not start. `evidence-oid4vp check` runs this same validation without
//! opening a socket or reading secret material. The rules that need the
//! certificate and key themselves (a SAN that names the public host, a key that
//! matches the leaf, an unexpired certificate, an Ed25519 key) read secret
//! material and therefore run at startup, in [`crate::client_identifier`].

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_audit::{AuditDestination, AuditDestinationError, AuditDestinationKind};
use registry_platform_config::{
    AuditKeyConfig, ConfigBlockErrorKind, JwksSource, OidcIssuerConfig, RemovedKey,
    RuntimeConfigLoader, RuntimeEnvelope, RuntimeFileCheck, SecretProvidersConfig, SecretReference,
    DEFAULT_STAND_IN,
};
use registry_platform_oidc::AccessTokenAlgorithm;
use registry_platform_yaml::{
    tagged_union, BoundedU32, BoundedU64, Diagnostic, ExternalId, Identified, LocalId, Report,
    Severity, UniqueIdList, UniqueList, Url,
};
use serde::{Deserialize, Serialize};

/// The `apiVersion` of a wallet protocol service runtime file.
pub const OID4VP_RUNTIME_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/oid4vp-runtime/v1alpha1";

/// The `kind` of a wallet protocol service runtime file.
pub const OID4VP_RUNTIME_KIND: &str = "EvidenceOid4vpRuntimeConfig";

/// The `$id` of the generated JSON Schema for a runtime file.
pub const OID4VP_RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/oid4vp-runtime/oid4vp-runtime.v1alpha1.schema.json";

/// The file name of the generated JSON Schema for a runtime file.
pub const RUNTIME_SCHEMA_FILE: &str = "oid4vp-runtime.schema.json";

/// Keys earlier releases read, each naming what replaces it.
const REMOVED_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "version",
        replacement: "Delete version; apiVersion and kind replace it.",
    },
    RemovedKey {
        path: "listener.address",
        replacement: "Write listener.bind as host:port, such as 127.0.0.1:8095.",
    },
    RemovedKey {
        path: "listener.port",
        replacement: "Write listener.bind as host:port, such as 127.0.0.1:8095.",
    },
];

/// The shared runtime reader for a runtime file.
#[must_use]
pub const fn loader() -> RuntimeConfigLoader {
    RuntimeConfigLoader::new(RuntimeEnvelope {
        api_version: OID4VP_RUNTIME_API_VERSION,
        kind: OID4VP_RUNTIME_KIND,
    })
    .removed_keys(REMOVED_KEYS)
    .require_trusted_ownership()
}

/// A runtime file the service refused, with every diagnostic that decided it.
#[derive(Debug)]
pub struct ConfigError {
    diagnostics: Vec<Diagnostic>,
    unavailable: bool,
}

impl ConfigError {
    /// Every finding, each naming the file as the path was given and each
    /// positioned at the member it concerns.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// The file could not be read at all, as opposed to read and refused.
    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        self.unavailable
    }

    /// The findings as the report a check prints.
    #[must_use]
    pub fn report(&self) -> Report {
        Report::new(self.diagnostics.clone())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let deciding = self
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == Severity::Error);
        match deciding {
            Some(diagnostic) if !self.unavailable => write!(
                formatter,
                "{} at {}: {}",
                diagnostic.code,
                if diagnostic.path.is_empty() {
                    "the document root"
                } else {
                    diagnostic.path.as_str()
                },
                diagnostic.message
            ),
            _ => formatter.write_str("the configuration file is unavailable"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// What an offline check of one runtime file found (CFG-CHECK-1).
#[derive(Debug, Default)]
pub struct RuntimeCheck {
    /// Every finding, each naming the file as the path was given and each
    /// positioned at the member it concerns.
    pub diagnostics: Vec<Diagnostic>,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
}

/// Check the runtime file at the absolute `path` as `evidence-oid4vp serve`
/// reads it, with no network, socket, or secret material, and report every
/// rule it breaks.
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only, and a rule that reads its value is
/// left out.
#[must_use]
pub fn check_file(path: &Path, substitute: bool) -> RuntimeCheck {
    let check = loader().check_offline::<VerifierDocument>(path, substitute, stand_in_for);
    let mut diagnostics = check.diagnostics.clone();
    if let Some(loaded) = &check.loaded {
        diagnostics.extend(
            loaded
                .config
                .findings()
                .iter()
                .filter(|finding| !reads_deferred_value(&check, finding))
                .map(|finding| positioned(&check, finding)),
        );
    }
    in_file_order(&mut diagnostics);
    RuntimeCheck {
        diagnostics,
        unavailable: check.unavailable,
    }
}

// ---------------------------------------------------------------------------
// The configuration the service runs on.
// ---------------------------------------------------------------------------

/// The listener a wallet and an adopter portal reach.
#[derive(Debug, Eq, PartialEq)]
pub struct ListenerConfig {
    pub bind: SocketAddr,
    pub maximum_request_bytes: u32,
    pub request_timeout_milliseconds: u64,
}

/// Optional operator-only metrics listener.
#[derive(Debug, Eq, PartialEq)]
pub struct MetricsListenerConfig {
    pub bind: SocketAddr,
}

/// The durable audit destination and keyed-pseudonym secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditConfig {
    pub key: AuditKeyConfig,
    pub destination: AuditDestinationKind,
    pub path: Option<PathBuf>,
    pub rotate_bytes: Option<u64>,
    pub retention_days: Option<u32>,
}

impl AuditConfig {
    pub fn destination(&self) -> Result<AuditDestination, AuditDestinationError> {
        AuditDestination::from_settings(
            self.destination,
            self.path.clone(),
            self.rotate_bytes,
            self.retention_days,
        )
    }
}

/// An access-token issuer this service accepts bearer tokens from, with the
/// rules a token must meet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenIssuerConfig {
    /// The issuer, audience and key source.
    pub provider: OidcIssuerConfig,
    pub algorithms: Vec<AccessTokenAlgorithm>,
    /// The scope every accepted token must carry.
    pub required_scope: String,
    /// The one client allowed to present a token, when the issuer is the
    /// Evidence service credential issuer.
    pub allowed_client: Option<String>,
    pub maximum_token_lifetime_seconds: u64,
}

/// The certificate chain and request-signing key behind an X.509 client
/// identifier, each a secret reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X509Material {
    pub certificate_chain_ref: SecretReference,
    pub signing_key_ref: SecretReference,
}

/// The DID and Ed25519 request-signing key behind a `decentralized_identifier`
/// client identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidMaterial {
    /// `did:web:<host>`, the public host alone.
    pub did: String,
    pub signing_key_ref: SecretReference,
}

/// The client id and Ed25519 request-signing key behind a `pre-registered`
/// client identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreRegisteredMaterial {
    /// The bare client identifier a wallet operator registers; it holds no
    /// `:`.
    pub client_id: String,
    pub signing_key_ref: SecretReference,
}

/// How one client identifier signs and names itself.
///
/// A closed choice, each with the same startup resolution in
/// [`crate::client_identifier`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientIdentifierKind {
    /// `x509_san_dns:<host>`: the leaf certificate names the public host.
    X509SanDns(X509Material),
    /// `x509_hash:<hash>`: the client identifier is the leaf certificate's
    /// SHA-256 hash.
    X509Hash(X509Material),
    /// `decentralized_identifier:did:web:<host>`: the key is published in the
    /// DID document this service serves.
    DecentralizedIdentifier(DidMaterial),
    /// The bare client identifier, registered with the wallet operator along
    /// with the keys this service publishes.
    PreRegistered(PreRegisteredMaterial),
}

/// One client identifier the service can present to a wallet, named by a local
/// identifier that policies refer to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdentifierConfig {
    pub id: String,
    pub kind: ClientIdentifierKind,
}

/// The accepted `enc` values of an encrypted authorization response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ResponseEncryption {
    A128GCM,
    A256GCM,
}

impl ResponseEncryption {
    /// The JWE `enc` value.
    #[must_use]
    pub const fn jwa_name(self) -> &'static str {
        match self {
            Self::A128GCM => "A128GCM",
            Self::A256GCM => "A256GCM",
        }
    }

    /// The decryption primitive for this value.
    #[must_use]
    pub const fn jwe_enc(self) -> registry_platform_crypto::jwe::JweEnc {
        match self {
            Self::A128GCM => registry_platform_crypto::jwe::JweEnc::A128Gcm,
            Self::A256GCM => registry_platform_crypto::jwe::JweEnc::A256Gcm,
        }
    }
}

/// One claim a credential query asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimQuery {
    /// The claims path: object member names from the credential root.
    pub path: Vec<String>,
}

/// One DCQL credential query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialQuery {
    pub id: String,
    pub vct_values: Vec<String>,
    /// The claims asked for; empty when the query requests none.
    pub claims: Vec<ClaimQuery>,
}

/// A trusted authority hint, an Authority Key Identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedAuthority {
    pub values: Vec<String>,
}

/// A presentation policy: what a portal may ask a wallet to present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConfig {
    pub id: String,
    /// The local id of the client identifier requests under this policy use.
    pub client_identifier: String,
    pub credentials: Vec<CredentialQuery>,
    /// Applied to every credential query. Empty omits `trusted_authorities`
    /// from the query, for a wallet that does not support it.
    pub trusted_authorities: Vec<TrustedAuthority>,
    pub accepted_response_encryption: Vec<ResponseEncryption>,
}

/// The bounds of the in-memory session store.
#[derive(Debug, Eq, PartialEq)]
pub struct SessionConfig {
    pub session_ttl_seconds: u64,
    pub result_ttl_seconds: u64,
    pub maximum_live_sessions: usize,
    /// The most presentation bytes the store holds across all sessions.
    pub maximum_held_presentation_bytes: u64,
}

/// Request-rate limits.
#[derive(Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    pub session_creations_per_principal_per_minute: u32,
    pub session_creation_burst: u32,
    pub wallet_requests_per_minute: u32,
    pub wallet_request_burst: u32,
    pub wallet_responses_per_minute: u32,
    pub wallet_response_burst: u32,
    pub responses_per_request_per_minute: u32,
    pub response_burst_per_request: u32,
    pub evidence_reads_per_minute: u32,
    pub evidence_read_burst: u32,
}

/// The whole startup configuration.
#[derive(Debug)]
pub struct Oid4vpConfig {
    /// The public origin wallets reach, without a trailing slash.
    pub public_base_url: String,
    /// The host of `public_base_url`, lowercase, without a port.
    pub public_host: String,
    pub listener: ListenerConfig,
    pub metrics_listener: Option<MetricsListenerConfig>,
    pub secret_providers: SecretProvidersConfig,
    pub audit: AuditConfig,
    /// The portal applicant token issuer.
    pub applicant_tokens: TokenIssuerConfig,
    /// The issuer of the Evidence service credential that reads results.
    pub evidence_credentials: TokenIssuerConfig,
    pub client_identifiers: Vec<ClientIdentifierConfig>,
    pub policies: Vec<PolicyConfig>,
    pub sessions: SessionConfig,
    pub rate_limits: RateLimitConfig,
}

impl Oid4vpConfig {
    /// Load and validate the runtime file at the absolute `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::load_reporting(path).map(|(config, _)| config)
    }

    /// Load and validate the runtime file at the absolute `path`, returning
    /// the warnings it carries beside the configuration.
    pub fn load_reporting(path: &Path) -> Result<(Self, Vec<Diagnostic>), ConfigError> {
        let mut check = loader().check_offline::<VerifierDocument>(path, true, stand_in_for);
        let Some(loaded) = check.loaded.take() else {
            return Err(ConfigError {
                diagnostics: std::mem::take(&mut check.diagnostics),
                unavailable: check.unavailable,
            });
        };
        let mut diagnostics: Vec<Diagnostic> = loaded
            .config
            .findings()
            .iter()
            .map(|finding| positioned(&check, finding))
            .collect();
        in_file_order(&mut diagnostics);
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
        {
            return Err(ConfigError {
                diagnostics,
                unavailable: false,
            });
        }
        Ok((loaded.config.into_config(), diagnostics))
    }

    /// The policy with this identifier.
    #[must_use]
    pub fn policy(&self, id: &str) -> Option<&PolicyConfig> {
        self.policies.iter().find(|policy| policy.id == id)
    }

    /// The client identifier with this local id.
    #[must_use]
    pub fn client_identifier(&self, id: &str) -> Option<&ClientIdentifierConfig> {
        self.client_identifiers
            .iter()
            .find(|identifier| identifier.id == id)
    }
}

// ---------------------------------------------------------------------------
// The document the reader decodes.
// ---------------------------------------------------------------------------

fn bounded_u32<const MIN: u32, const MAX: u32>(value: u32) -> BoundedU32<MIN, MAX> {
    BoundedU32::new(value).expect("a declared default is within its bounds")
}

fn bounded_u64<const MIN: u64, const MAX: u64>(value: u64) -> BoundedU64<MIN, MAX> {
    BoundedU64::new(value).expect("a declared default is within its bounds")
}

fn default_maximum_request_bytes() -> BoundedU32<1_024, 1_048_576> {
    bounded_u32(16 * 1024)
}

fn default_request_timeout_milliseconds() -> BoundedU64<1, 30_000> {
    bounded_u64(5_000)
}

fn default_algorithms() -> UniqueList<AccessTokenAlgorithm> {
    UniqueList::new(vec![AccessTokenAlgorithm::ES256]).expect("one algorithm is distinct")
}

fn default_maximum_token_lifetime_seconds() -> BoundedU64<60, 3_600> {
    bounded_u64(900)
}

fn default_accepted_response_encryption() -> UniqueList<ResponseEncryption> {
    UniqueList::new(vec![
        ResponseEncryption::A128GCM,
        ResponseEncryption::A256GCM,
    ])
    .expect("two values are distinct")
}

fn default_session_ttl_seconds() -> BoundedU64<30, 900> {
    bounded_u64(300)
}

fn default_result_ttl_seconds() -> BoundedU64<30, 3_600> {
    bounded_u64(1_800)
}

fn default_maximum_live_sessions() -> BoundedU32<1, 1_048_576> {
    bounded_u32(4_096)
}

fn default_maximum_held_presentation_bytes() -> BoundedU64<1_048_576, 17_179_869_184> {
    bounded_u64(268_435_456)
}

fn default_session_creations_per_principal_per_minute() -> BoundedU32<1, 100_000> {
    bounded_u32(30)
}

fn default_session_creation_burst() -> BoundedU32<1, 100_000> {
    bounded_u32(10)
}

fn default_wallet_requests_per_minute() -> BoundedU32<1, 1_000_000> {
    bounded_u32(600)
}

fn default_wallet_request_burst() -> BoundedU32<1, 100_000> {
    bounded_u32(100)
}

fn default_wallet_responses_per_minute() -> BoundedU32<1, 1_000_000> {
    bounded_u32(600)
}

fn default_wallet_response_burst() -> BoundedU32<1, 100_000> {
    bounded_u32(100)
}

fn default_responses_per_request_per_minute() -> BoundedU32<1, 6_000> {
    bounded_u32(12)
}

fn default_response_burst_per_request() -> BoundedU32<1, 1_000> {
    bounded_u32(6)
}

fn default_evidence_reads_per_minute() -> BoundedU32<1, 1_000_000> {
    bounded_u32(600)
}

fn default_evidence_read_burst() -> BoundedU32<1, 100_000> {
    bounded_u32(100)
}

/// The wallet protocol service runtime file: one deployment of the OpenID4VP
/// verifier front end for Evidence.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifierDocument {
    /// The format version of this file.
    pub api_version: String,
    /// The document kind.
    pub kind: String,
    /// The public origin wallets reach this service at: a bare https origin
    /// with no path, query, or fragment. The response URI and the request URI
    /// are built from it. A trailing slash is removed.
    pub public_base_url: Url,
    /// The listener a wallet and a portal reach.
    pub listener: ListenerDocument,
    /// The optional operator-only metrics listener: a loopback or private
    /// address the service listener does not use. Absent means no metrics
    /// endpoint exists.
    #[serde(default)]
    pub metrics_listener: Option<registry_platform_config::ListenerConfig>,
    /// The secret providers the `*Ref` members may name.
    pub secret_providers: SecretProvidersConfig,
    /// The required durable audit journal.
    pub audit: AuditDocument,
    /// The issuer of the applicant tokens a portal presents to create a
    /// session.
    pub applicant_tokens: ApplicantTokensDocument,
    /// The issuer of the Evidence service credential that reads a result.
    pub evidence_credentials: EvidenceCredentialsDocument,
    /// How the service identifies itself to a wallet: one or more client
    /// identifiers, each named by a local id. Every policy names the one it
    /// uses, and every identifier is used by at least one policy.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 8)))]
    pub client_identifiers: UniqueIdList<ClientIdentifierDocument>,
    /// What a portal may ask a wallet to present. At least one.
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub policies: UniqueIdList<PolicyDocument>,
    /// The bounds of the in-memory session store.
    #[serde(default)]
    pub sessions: SessionsDocument,
    /// Request-rate limits.
    #[serde(default)]
    pub rate_limits: RateLimitsDocument,
}

/// The process-local audit destination and keyed-pseudonym secret.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditDocument {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/audit-key"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub key: AuditKeyConfig,
    #[serde(default)]
    pub destination: AuditDestinationKind,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(extend("pattern" = "^/")))]
    pub path: Option<PathBuf>,
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = registry_platform_audit::MIN_AUDIT_ROTATE_BYTES, max = u32::MAX))
    )]
    pub rotate_bytes: Option<u64>,
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = registry_platform_audit::MAX_AUDIT_RETAIN_DAYS))
    )]
    pub retention_days: Option<u32>,
}

impl AuditDocument {
    fn destination(&self) -> Result<AuditDestination, AuditDestinationError> {
        AuditDestination::from_settings(
            self.destination,
            self.path.clone(),
            self.rotate_bytes,
            self.retention_days,
        )
    }
}

/// The listener a wallet and a portal reach.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerDocument {
    /// `bind`: the socket address the listener binds.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/listener"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub address: registry_platform_config::ListenerConfig,
    /// The largest request body accepted, in bytes.
    #[serde(default = "default_maximum_request_bytes")]
    pub maximum_request_bytes: BoundedU32<1_024, 1_048_576>,
    /// How long one request may take, in milliseconds.
    #[serde(default = "default_request_timeout_milliseconds")]
    pub request_timeout_milliseconds: BoundedU64<1, 30_000>,
}

/// The issuer of applicant tokens.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicantTokensDocument {
    /// The issuer, the audience every token carries, and the key source.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/provider"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub provider: OidcIssuerConfig,
    /// The signature algorithms a token may use; one family only.
    #[serde(default = "default_algorithms")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 5)))]
    pub algorithms: UniqueList<AccessTokenAlgorithm>,
    /// The scope every token must carry to create a session. The creating
    /// principal is the token's issuer, subject, and client.
    pub required_scope: ExternalId,
    /// The longest lifetime a token may carry, in seconds.
    #[serde(default = "default_maximum_token_lifetime_seconds")]
    pub maximum_token_lifetime_seconds: BoundedU64<60, 3_600>,
}

/// The issuer of the Evidence service credential.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceCredentialsDocument {
    /// The issuer, the audience every token carries, and the key source.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/provider"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub provider: OidcIssuerConfig,
    /// The signature algorithms a token may use; one family only.
    #[serde(default = "default_algorithms")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 5)))]
    pub algorithms: UniqueList<AccessTokenAlgorithm>,
    /// The one client allowed to read results: Evidence's service client.
    pub allowed_client: ExternalId,
    /// The scope the Evidence token must carry to read a result.
    pub required_scope: ExternalId,
    /// The longest lifetime a token may carry, in seconds.
    #[serde(default = "default_maximum_token_lifetime_seconds")]
    pub maximum_token_lifetime_seconds: BoundedU64<60, 3_600>,
}

/// One client identifier. The `type` member names the choice.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum ClientIdentifierDocument {
    /// `x509_san_dns`: the leaf certificate's DNS subject alternative name is
    /// the public host. Requests are signed with the certificate's key (ES256).
    X509SanDns {
        /// The identifier policies name in `clientIdentifier`.
        id: LocalId,
        /// The PEM certificate chain, leaf first, as a secret reference.
        certificate_chain_ref: SecretReference,
        /// The private JWK that signs request objects, as a secret reference.
        /// It must be the leaf certificate's key.
        signing_key_ref: SecretReference,
    },
    /// `x509_hash`: the client identifier is the SHA-256 hash of the leaf
    /// certificate. Requests are signed with the certificate's key (ES256).
    X509Hash {
        /// The identifier policies name in `clientIdentifier`.
        id: LocalId,
        /// The PEM certificate chain, leaf first, as a secret reference.
        certificate_chain_ref: SecretReference,
        /// The private JWK that signs request objects, as a secret reference.
        /// It must be the leaf certificate's key.
        signing_key_ref: SecretReference,
    },
    /// `decentralized_identifier` with a `did:web` DID. The service serves the
    /// DID document at `/.well-known/did.json`. Requests are signed with an
    /// Ed25519 key (EdDSA).
    DecentralizedIdentifier {
        /// The identifier policies name in `clientIdentifier`.
        id: LocalId,
        /// `did:web:` and the host of `publicBaseUrl`, with no port and no
        /// path.
        did: ExternalId,
        /// The private Ed25519 JWK (`kty` OKP, `alg` EdDSA) that signs request
        /// objects, as a secret reference.
        signing_key_ref: SecretReference,
    },
    /// `pre-registered`: the client identifier is the bare `clientId` a wallet
    /// operator registers, with this service's `/v1/jwks` as the key set.
    /// Requests are signed with an Ed25519 key (EdDSA).
    PreRegistered {
        /// The identifier policies name in `clientIdentifier`.
        id: LocalId,
        /// The client identifier as registered with the wallet operator. It
        /// holds no `:`, which is what marks it as pre-registered.
        client_id: ExternalId,
        /// The private Ed25519 JWK (`kty` OKP, `alg` EdDSA) that signs request
        /// objects, as a secret reference.
        signing_key_ref: SecretReference,
    },
}

tagged_union!(ClientIdentifierDocument);

impl Identified for ClientIdentifierDocument {
    fn id(&self) -> &str {
        let (Self::X509SanDns { id, .. }
        | Self::X509Hash { id, .. }
        | Self::DecentralizedIdentifier { id, .. }
        | Self::PreRegistered { id, .. }) = self;
        id.as_str()
    }
}

impl ClientIdentifierDocument {
    /// The secret references this identifier holds, each with the member that
    /// carries it.
    fn refs(&self) -> Vec<(&'static str, &SecretReference)> {
        match self {
            Self::X509SanDns {
                certificate_chain_ref,
                signing_key_ref,
                ..
            }
            | Self::X509Hash {
                certificate_chain_ref,
                signing_key_ref,
                ..
            } => vec![
                ("certificateChainRef", certificate_chain_ref),
                ("signingKeyRef", signing_key_ref),
            ],
            Self::DecentralizedIdentifier {
                signing_key_ref, ..
            }
            | Self::PreRegistered {
                signing_key_ref, ..
            } => vec![("signingKeyRef", signing_key_ref)],
        }
    }

    fn into_config(self) -> ClientIdentifierConfig {
        let id = self.id().to_owned();
        let kind = match self {
            Self::X509SanDns {
                certificate_chain_ref,
                signing_key_ref,
                ..
            } => ClientIdentifierKind::X509SanDns(X509Material {
                certificate_chain_ref,
                signing_key_ref,
            }),
            Self::X509Hash {
                certificate_chain_ref,
                signing_key_ref,
                ..
            } => ClientIdentifierKind::X509Hash(X509Material {
                certificate_chain_ref,
                signing_key_ref,
            }),
            Self::DecentralizedIdentifier {
                did,
                signing_key_ref,
                ..
            } => ClientIdentifierKind::DecentralizedIdentifier(DidMaterial {
                did: did.into_string(),
                signing_key_ref,
            }),
            Self::PreRegistered {
                client_id,
                signing_key_ref,
                ..
            } => ClientIdentifierKind::PreRegistered(PreRegisteredMaterial {
                client_id: client_id.into_string(),
                signing_key_ref,
            }),
        };
        ClientIdentifierConfig { id, kind }
    }
}

/// The only credential format the service requests.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum CredentialFormat {
    #[serde(rename = "dc+sd-jwt")]
    #[cfg_attr(feature = "schema", schemars(rename = "dc+sd-jwt"))]
    DcSdJwt,
}

/// The trusted authority type; only `aki` is offered.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TrustedAuthorityType {
    Aki,
}

/// One claim a credential query asks for.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimQueryDocument {
    /// The claims path: object member names from the credential root, 1 to 8.
    /// A name may repeat along a path (`address`, `address`), so this is an
    /// ordered list, not a set.
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = 8), inner(length(min = 1, max = 256)))
    )]
    pub path: Vec<String>,
}

/// One DCQL credential query.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialQueryDocument {
    /// The query identifier the wallet keys its `vp_token` by.
    pub id: LocalId,
    /// The credential format, `dc+sd-jwt`.
    pub format: CredentialFormat,
    /// The credential types (`vct`) the wallet may present for this query, 1
    /// to 16.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 16)))]
    pub vct_values: UniqueList<ExternalId>,
    /// The claims asked for, 1 to 64. Ask only for what the policy needs.
    /// Absent, the query requests no selectively disclosable claim and the
    /// wallet presents the credential with none (OpenID4VP 1.0 section 6.4.1);
    /// an empty list is refused.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 64)))]
    pub claims: Option<Vec<ClaimQueryDocument>>,
}

impl Identified for CredentialQueryDocument {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// A trusted authority hint passed to the wallet for minimisation. The service
/// still decides trust itself.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedAuthorityDocument {
    /// The authority type.
    #[serde(rename = "type")]
    pub kind: TrustedAuthorityType,
    /// Authority Key Identifiers, base64url, 1 to 16.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 16)))]
    pub values: UniqueList<ExternalId>,
}

/// A presentation policy.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyDocument {
    /// The policy identifier a portal names when it creates a session.
    pub id: LocalId,
    /// The client identifier requests under this policy use: the `id` of an
    /// entry in `clientIdentifiers`.
    pub client_identifier: LocalId,
    /// The credential queries, 1 to 8.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 8)))]
    pub credentials: UniqueIdList<CredentialQueryDocument>,
    /// Trusted authority hints applied to every credential query. Omit for a
    /// wallet that does not support them.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 4)))]
    pub trusted_authorities: Option<Vec<TrustedAuthorityDocument>>,
    /// The `enc` values of an encrypted authorization response the service
    /// accepts and advertises.
    #[serde(default = "default_accepted_response_encryption")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 2)))]
    pub accepted_response_encryption: UniqueList<ResponseEncryption>,
}

impl Identified for PolicyDocument {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// The bounds of the in-memory session store.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionsDocument {
    /// How long a session waits for the wallet's response, in seconds. The
    /// request object expires with it.
    #[serde(default = "default_session_ttl_seconds")]
    pub session_ttl_seconds: BoundedU64<30, 900>,
    /// How long an accepted presentation is held for Evidence to read, in
    /// seconds.
    #[serde(default = "default_result_ttl_seconds")]
    pub result_ttl_seconds: BoundedU64<30, 3_600>,
    /// How many sessions the store holds. A full store refuses new sessions
    /// rather than forgetting live ones.
    #[serde(default = "default_maximum_live_sessions")]
    pub maximum_live_sessions: BoundedU32<1, 1_048_576>,
    /// The most presentation bytes the store holds across all sessions, from
    /// the moment a response is accepted until its session ends or its result
    /// expires. A response that would exceed it is refused with a retryable
    /// 503; the sessions already holding results are unaffected.
    #[serde(default = "default_maximum_held_presentation_bytes")]
    pub maximum_held_presentation_bytes: BoundedU64<1_048_576, 17_179_869_184>,
}

impl Default for SessionsDocument {
    fn default() -> Self {
        Self {
            session_ttl_seconds: default_session_ttl_seconds(),
            result_ttl_seconds: default_result_ttl_seconds(),
            maximum_live_sessions: default_maximum_live_sessions(),
            maximum_held_presentation_bytes: default_maximum_held_presentation_bytes(),
        }
    }
}

/// Request-rate limits.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitsDocument {
    /// Sessions one principal may create per minute.
    #[serde(default = "default_session_creations_per_principal_per_minute")]
    pub session_creations_per_principal_per_minute: BoundedU32<1, 100_000>,
    /// The most sessions one principal may create in a burst.
    #[serde(default = "default_session_creation_burst")]
    pub session_creation_burst: BoundedU32<1, 100_000>,
    /// Request object fetches per minute, across all wallets.
    #[serde(default = "default_wallet_requests_per_minute")]
    pub wallet_requests_per_minute: BoundedU32<1, 1_000_000>,
    /// The most wallet requests admitted in a burst.
    #[serde(default = "default_wallet_request_burst")]
    pub wallet_request_burst: BoundedU32<1, 100_000>,
    /// Wallet responses per minute across all sessions. Every attempt counts,
    /// including those for unknown request identifiers.
    #[serde(default = "default_wallet_responses_per_minute")]
    pub wallet_responses_per_minute: BoundedU32<1, 1_000_000>,
    /// The most wallet responses admitted in a burst.
    #[serde(default = "default_wallet_response_burst")]
    pub wallet_response_burst: BoundedU32<1, 100_000>,
    /// Response attempts per minute against one session.
    #[serde(default = "default_responses_per_request_per_minute")]
    pub responses_per_request_per_minute: BoundedU32<1, 6_000>,
    /// The most response attempts against one session in a burst.
    #[serde(default = "default_response_burst_per_request")]
    pub response_burst_per_request: BoundedU32<1, 1_000>,
    /// Result reads per minute for one Evidence client.
    #[serde(default = "default_evidence_reads_per_minute")]
    pub evidence_reads_per_minute: BoundedU32<1, 1_000_000>,
    /// The most result reads one Evidence client may make in a burst.
    #[serde(default = "default_evidence_read_burst")]
    pub evidence_read_burst: BoundedU32<1, 100_000>,
}

impl Default for RateLimitsDocument {
    fn default() -> Self {
        Self {
            session_creations_per_principal_per_minute:
                default_session_creations_per_principal_per_minute(),
            session_creation_burst: default_session_creation_burst(),
            wallet_requests_per_minute: default_wallet_requests_per_minute(),
            wallet_request_burst: default_wallet_request_burst(),
            wallet_responses_per_minute: default_wallet_responses_per_minute(),
            wallet_response_burst: default_wallet_response_burst(),
            responses_per_request_per_minute: default_responses_per_request_per_minute(),
            response_burst_per_request: default_response_burst_per_request(),
            evidence_reads_per_minute: default_evidence_reads_per_minute(),
            evidence_read_burst: default_evidence_read_burst(),
        }
    }
}

// ---------------------------------------------------------------------------
// Rules beyond shape.
// ---------------------------------------------------------------------------

/// One rule a decoded document breaks, at the member it concerns.
#[derive(Debug)]
struct Finding {
    severity: Severity,
    code: &'static str,
    pointer: String,
    message: &'static str,
    action: &'static str,
    /// Members besides `pointer` whose value decided the finding.
    reads: &'static [&'static str],
}

impl Finding {
    fn error(
        code: &'static str,
        pointer: impl Into<String>,
        message: &'static str,
        action: &'static str,
    ) -> Self {
        Self {
            severity: Severity::Error,
            code,
            pointer: pointer.into(),
            message,
            action,
            reads: &[],
        }
    }

    fn reading(mut self, reads: &'static [&'static str]) -> Self {
        self.reads = reads;
        self
    }
}

const HTTPS_REQUIRED: &str = "evidence.oid4vp.https-required";

impl VerifierDocument {
    /// Every rule a decoded document breaks beyond its shape.
    fn findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.public_url_findings(&mut findings);
        binding_findings(
            self.listener.address.bind.socket_addr(),
            self.metrics_listener
                .map(|metrics| metrics.bind.socket_addr()),
            &mut findings,
        );
        self.secret_findings(&mut findings);
        self.client_identifier_findings(&mut findings);
        self.issuer_findings(&mut findings);
        self.audit_findings(&mut findings);
        self.policy_findings(&mut findings);
        findings
    }

    fn public_url_findings(&self, findings: &mut Vec<Finding>) {
        const POINTER: &str = "/publicBaseUrl";
        if !self.public_base_url.is_https() {
            findings.push(Finding::error(
                HTTPS_REQUIRED,
                POINTER,
                "the public base URL must use https",
                "Write the public origin wallets reach as an https URL.",
            ));
        }
        let parsed = self.public_base_url.to_url();
        if parsed.query().is_some() || parsed.fragment().is_some() {
            findings.push(Finding::error(
                "evidence.oid4vp.url-query-or-fragment",
                POINTER,
                "the public base URL must not carry a query or fragment",
                "Remove the query and fragment from the URL.",
            ));
        }
        if parsed.path() != "/" {
            findings.push(Finding::error(
                "evidence.oid4vp.public-base-path",
                POINTER,
                "the public base URL must be a bare origin with no path",
                "Write the public base URL as scheme, host, and port only, such as https://verifier.example.org.",
            ));
        }
        let is_domain = matches!(parsed.host(), Some(url::Host::Domain(_)));
        if !is_domain
            && self
                .client_identifiers
                .iter()
                .any(|identifier| matches!(identifier, ClientIdentifierDocument::X509SanDns { .. }))
        {
            findings.push(
                Finding::error(
                    "evidence.oid4vp.san-dns-host",
                    POINTER,
                    "an x509-san-dns client identifier needs a DNS name as the public host, not an IP address",
                    "Write the public base URL with a DNS host name, or choose the x509-hash client identifier.",
                )
                .reading(&["/clientIdentifiers"]),
            );
        }
        if parsed.port().is_some()
            && self.client_identifiers.iter().any(|identifier| {
                matches!(
                    identifier,
                    ClientIdentifierDocument::DecentralizedIdentifier { .. }
                )
            })
        {
            findings.push(
                Finding::error(
                    "evidence.oid4vp.did-web-public-port",
                    POINTER,
                    "a did:web client identifier resolves at the host on the default https port, so the public base URL must not name a port",
                    "Serve the public origin on the default https port, or remove the decentralized-identifier client identifier.",
                )
                .reading(&["/clientIdentifiers"]),
            );
        }
    }

    fn client_identifier_findings(&self, findings: &mut Vec<Finding>) {
        let public_host = self
            .public_base_url
            .to_url()
            .host_str()
            .unwrap_or_default()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        for (index, identifier) in self.client_identifiers.iter().enumerate() {
            match identifier {
                ClientIdentifierDocument::DecentralizedIdentifier { did, .. } => {
                    let pointer = format!("/clientIdentifiers/{index}/did");
                    match did_web_host(did.as_str()) {
                        Err(DidWebFault::NotDidWeb) => findings.push(Finding::error(
                            "evidence.oid4vp.did-web-invalid",
                            pointer,
                            "the DID must be did:web: followed by a host",
                            "Write the DID as did:web: and the host of publicBaseUrl.",
                        )),
                        Err(DidWebFault::PortOrPath) => findings.push(Finding::error(
                            "evidence.oid4vp.did-web-port-or-path",
                            pointer,
                            "the DID must name the host alone, with no port and no path",
                            "Write the DID as did:web: and the host of publicBaseUrl, without a port or path segments.",
                        )),
                        Ok(host) if !host.eq_ignore_ascii_case(&public_host) => {
                            findings.push(
                                Finding::error(
                                    "evidence.oid4vp.did-web-host",
                                    pointer,
                                    "the DID host must be the host of publicBaseUrl",
                                    "Write the DID with the host of publicBaseUrl.",
                                )
                                .reading(&["/publicBaseUrl"]),
                            );
                        }
                        Ok(_) => {}
                    }
                }
                ClientIdentifierDocument::PreRegistered { client_id, .. }
                    if client_id.as_str().contains(':') =>
                {
                    findings.push(Finding::error(
                        "evidence.oid4vp.pre-registered-client-id",
                        format!("/clientIdentifiers/{index}/clientId"),
                        "a pre-registered client id must not contain a colon; with one a wallet reads a client identifier prefix",
                        "Write the client id as a bare name, such as evidence-verifier.",
                    ));
                }
                _ => {}
            }
        }
        for (index, policy) in self.policies.iter().enumerate() {
            if self
                .client_identifiers
                .get(policy.client_identifier.as_str())
                .is_none()
            {
                findings.push(
                    Finding::error(
                        "evidence.oid4vp.unknown-client-identifier",
                        format!("/policies/{index}/clientIdentifier"),
                        "this policy names a client identifier that clientIdentifiers does not define",
                        "Name the id of an entry in clientIdentifiers.",
                    )
                    .reading(&["/clientIdentifiers"]),
                );
            }
        }
        for (index, identifier) in self.client_identifiers.iter().enumerate() {
            // With no policy at all, no-policies already says what to fix.
            if !self.policies.is_empty()
                && !self
                    .policies
                    .iter()
                    .any(|policy| policy.client_identifier.as_str() == identifier.id())
            {
                findings.push(
                    Finding::error(
                        "evidence.oid4vp.unused-client-identifier",
                        format!("/clientIdentifiers/{index}/id"),
                        "no policy uses this client identifier",
                        "Name it in a policy's clientIdentifier, or remove it.",
                    )
                    .reading(&["/policies"]),
                );
            }
        }
    }

    fn secret_findings(&self, findings: &mut Vec<Finding>) {
        if let Err(error) = self.secret_providers.check() {
            findings.push(match error.kind() {
                ConfigBlockErrorKind::RelativePath => Finding::error(
                    "evidence.oid4vp.secret-file-root",
                    "/secretProviders/file/root",
                    "the file secret provider root must be an absolute path",
                    "Write secretProviders.file.root as an absolute directory path.",
                ),
                _ => Finding::error(
                    "evidence.oid4vp.secret-providers",
                    "/secretProviders",
                    "secretProviders must enable the file provider, the environment provider, or both",
                    "Declare secretProviders.file with an absolute root, or secretProviders.environment as {}.",
                ),
            });
            return;
        }
        for (index, identifier) in self.client_identifiers.iter().enumerate() {
            for (member, reference) in identifier.refs() {
                let pointer = format!("/clientIdentifiers/{index}/{member}");
                if self
                    .secret_providers
                    .check_reference(&pointer, reference.as_str())
                    .is_err()
                {
                    findings.push(
                        Finding::error(
                            "evidence.oid4vp.secret-provider-disabled",
                            pointer,
                            "this secret reference names a provider this file does not enable",
                            "Declare the provider the reference names under secretProviders, or reference the secret through an enabled provider.",
                        )
                        .reading(&["/secretProviders"]),
                    );
                }
            }
        }
        if self.audit.key.check(&self.secret_providers).is_err() {
            findings.push(
                Finding::error(
                    "evidence.oid4vp.audit-secret-provider-disabled",
                    "/audit/hashKeyRef",
                    "the audit hash key reference names a secret provider this file does not enable",
                    "Declare the provider the reference names under secretProviders, or reference the audit key through an enabled provider.",
                )
                .reading(&["/secretProviders"]),
            );
        }
        for (pointer, provider) in [
            ("/applicantTokens", &self.applicant_tokens.provider),
            ("/evidenceCredentials", &self.evidence_credentials.provider),
        ] {
            if let JwksSource::Static { document_ref } = &provider.jwks_source {
                if self
                    .secret_providers
                    .check_reference(pointer, document_ref)
                    .is_err()
                {
                    findings.push(
                        Finding::error(
                            "evidence.oid4vp.secret-provider-disabled",
                            format!("{pointer}/jwksSource/documentRef"),
                            "this secret reference names a provider this file does not enable",
                            "Declare the provider the reference names under secretProviders, or reference the secret through an enabled provider.",
                        )
                        .reading(&["/secretProviders"]),
                    );
                }
            }
        }
    }

    fn issuer_findings(&self, findings: &mut Vec<Finding>) {
        for (field, pointer, provider) in [
            (
                "applicantTokens",
                "/applicantTokens",
                &self.applicant_tokens.provider,
            ),
            (
                "evidenceCredentials",
                "/evidenceCredentials",
                &self.evidence_credentials.provider,
            ),
        ] {
            let Err(error) = provider.check(field, false) else {
                continue;
            };
            let member = error.field().rsplit('.').next().unwrap_or_default();
            let (message, action) = match error.kind() {
                ConfigBlockErrorKind::InvalidAudience => (
                    "the audience must be non-empty text without control characters",
                    "Write the audience the token issuer puts in aud.",
                ),
                _ => (
                    "the issuer and its key set must be absolute https URLs without credentials, query, or fragment",
                    "Write an https URL, or set allowInsecureHttp: true for a declared plain-HTTP issuer.",
                ),
            };
            let located = match member {
                "audience" | "issuer" => format!("{pointer}/{member}"),
                "uri" => format!("{pointer}/jwksSource/uri"),
                _ => format!("{pointer}/jwksSource"),
            };
            findings.push(Finding::error(
                "evidence.oid4vp.invalid-issuer",
                located,
                message,
                action,
            ));
        }
    }

    fn audit_findings(&self, findings: &mut Vec<Finding>) {
        if let Err(error) = self.audit.destination() {
            let pointer = match error {
                AuditDestinationError::MissingPath
                | AuditDestinationError::RelativePath
                | AuditDestinationError::InvalidPathComponent
                | AuditDestinationError::NoFileName
                | AuditDestinationError::FileNameTooLong { .. }
                | AuditDestinationError::PathNamesReservedCompanion { .. }
                | AuditDestinationError::FileOnlyField { field: "path" } => "/audit/path",
                AuditDestinationError::FileOnlyField {
                    field: "rotateBytes",
                }
                | AuditDestinationError::RotateBytesOutOfRange { .. } => "/audit/rotateBytes",
                AuditDestinationError::FileOnlyField {
                    field: "retainDays",
                }
                | AuditDestinationError::RetainDaysOutOfRange { .. } => "/audit/retentionDays",
                _ => "/audit",
            };
            findings.push(Finding::error(
                "evidence.oid4vp.invalid-audit",
                pointer,
                "the audit destination settings are invalid",
                "Use stdout without file settings, or an absolute file path with supported rotation and retention values.",
            ));
        }
    }

    fn policy_findings(&self, findings: &mut Vec<Finding>) {
        if self.policies.is_empty() {
            findings.push(Finding::error(
                "evidence.oid4vp.no-policies",
                "/policies",
                "at least one presentation policy is required",
                "Declare a policy with an id and at least one credential query.",
            ));
        }
        for (index, policy) in self.policies.iter().enumerate() {
            for (credential_index, credential) in policy.credentials.iter().enumerate() {
                let claims = credential.claims.as_deref().unwrap_or_default();
                if credential.claims.is_some() && !(1..=64).contains(&claims.len()) {
                    findings.push(Finding::error(
                        "evidence.oid4vp.invalid-claims-count",
                        format!("/policies/{index}/credentials/{credential_index}/claims"),
                        "a credential query lists 1 to 64 claims when it has a claims member",
                        "Omit `claims` to request no claim, or list the claims the policy needs.",
                    ));
                }
                for (claim_index, claim) in claims.iter().enumerate() {
                    let bounded = !claim.path.is_empty()
                        && claim.path.len() <= 8
                        && claim
                            .path
                            .iter()
                            .all(|segment| (1..=256).contains(&segment.len()));
                    if !bounded {
                        findings.push(Finding::error(
                            "evidence.oid4vp.invalid-claim-path",
                            format!(
                                "/policies/{index}/credentials/{credential_index}/claims/{claim_index}/path"
                            ),
                            "a claims path holds 1 to 8 non-empty names of at most 256 bytes",
                            "Write the claim as a path of object member names.",
                        ));
                    }
                }
            }
            let Some(authorities) = &policy.trusted_authorities else {
                continue;
            };
            for (authority_index, authority) in authorities.iter().enumerate() {
                for (value_index, value) in authority.values.iter().enumerate() {
                    if URL_SAFE_NO_PAD.decode(value.as_str()).is_err() {
                        findings.push(Finding::error(
                            "evidence.oid4vp.invalid-authority-key-identifier",
                            format!(
                                "/policies/{index}/trustedAuthorities/{authority_index}/values/{value_index}"
                            ),
                            "an Authority Key Identifier must be base64url without padding",
                            "Write the key identifier as unpadded base64url.",
                        ));
                    }
                }
            }
        }
    }

    fn into_config(self) -> Oid4vpConfig {
        let parsed = self.public_base_url.to_url();
        let public_host = parsed
            .host_str()
            .unwrap_or_default()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let public_base_url = self
            .public_base_url
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        let accepted_algorithms = |list: UniqueList<AccessTokenAlgorithm>| list.into_vec();
        Oid4vpConfig {
            public_base_url,
            public_host,
            listener: ListenerConfig {
                bind: self.listener.address.bind.socket_addr(),
                maximum_request_bytes: self.listener.maximum_request_bytes.get(),
                request_timeout_milliseconds: self.listener.request_timeout_milliseconds.get(),
            },
            metrics_listener: self.metrics_listener.map(|metrics| MetricsListenerConfig {
                bind: metrics.bind.socket_addr(),
            }),
            secret_providers: self.secret_providers,
            audit: AuditConfig {
                key: self.audit.key,
                destination: self.audit.destination,
                path: self.audit.path,
                rotate_bytes: self.audit.rotate_bytes,
                retention_days: self.audit.retention_days,
            },
            applicant_tokens: TokenIssuerConfig {
                provider: self.applicant_tokens.provider,
                algorithms: accepted_algorithms(self.applicant_tokens.algorithms),
                required_scope: self.applicant_tokens.required_scope.into_string(),
                allowed_client: None,
                maximum_token_lifetime_seconds: self
                    .applicant_tokens
                    .maximum_token_lifetime_seconds
                    .get(),
            },
            evidence_credentials: TokenIssuerConfig {
                provider: self.evidence_credentials.provider,
                algorithms: accepted_algorithms(self.evidence_credentials.algorithms),
                required_scope: self.evidence_credentials.required_scope.into_string(),
                allowed_client: Some(self.evidence_credentials.allowed_client.into_string()),
                maximum_token_lifetime_seconds: self
                    .evidence_credentials
                    .maximum_token_lifetime_seconds
                    .get(),
            },
            client_identifiers: self
                .client_identifiers
                .into_vec()
                .into_iter()
                .map(ClientIdentifierDocument::into_config)
                .collect(),
            policies: self
                .policies
                .into_vec()
                .into_iter()
                .map(PolicyDocument::into_config)
                .collect(),
            sessions: SessionConfig {
                session_ttl_seconds: self.sessions.session_ttl_seconds.get(),
                result_ttl_seconds: self.sessions.result_ttl_seconds.get(),
                maximum_live_sessions: self.sessions.maximum_live_sessions.get() as usize,
                maximum_held_presentation_bytes: self
                    .sessions
                    .maximum_held_presentation_bytes
                    .get(),
            },
            rate_limits: RateLimitConfig {
                session_creations_per_principal_per_minute: self
                    .rate_limits
                    .session_creations_per_principal_per_minute
                    .get(),
                session_creation_burst: self.rate_limits.session_creation_burst.get(),
                wallet_requests_per_minute: self.rate_limits.wallet_requests_per_minute.get(),
                wallet_request_burst: self.rate_limits.wallet_request_burst.get(),
                wallet_responses_per_minute: self.rate_limits.wallet_responses_per_minute.get(),
                wallet_response_burst: self.rate_limits.wallet_response_burst.get(),
                responses_per_request_per_minute: self
                    .rate_limits
                    .responses_per_request_per_minute
                    .get(),
                response_burst_per_request: self.rate_limits.response_burst_per_request.get(),
                evidence_reads_per_minute: self.rate_limits.evidence_reads_per_minute.get(),
                evidence_read_burst: self.rate_limits.evidence_read_burst.get(),
            },
        }
    }
}

impl PolicyDocument {
    fn into_config(self) -> PolicyConfig {
        PolicyConfig {
            id: self.id.into_string(),
            client_identifier: self.client_identifier.into_string(),
            credentials: self
                .credentials
                .into_vec()
                .into_iter()
                .map(|query| CredentialQuery {
                    id: query.id.into_string(),
                    vct_values: query
                        .vct_values
                        .into_vec()
                        .into_iter()
                        .map(ExternalId::into_string)
                        .collect(),
                    claims: query
                        .claims
                        .unwrap_or_default()
                        .into_iter()
                        .map(|claim| ClaimQuery { path: claim.path })
                        .collect(),
                })
                .collect(),
            trusted_authorities: self
                .trusted_authorities
                .unwrap_or_default()
                .into_iter()
                .map(|authority| TrustedAuthority {
                    values: authority
                        .values
                        .into_vec()
                        .into_iter()
                        .map(ExternalId::into_string)
                        .collect(),
                })
                .collect(),
            accepted_response_encryption: self.accepted_response_encryption.into_vec(),
        }
    }
}

/// Why a DID is not `did:web:<host>`.
enum DidWebFault {
    NotDidWeb,
    PortOrPath,
}

/// The host of a `did:web` DID that names a host alone. A port is written
/// `%3A` and a path is further `:`-separated segments; neither is accepted,
/// because a wallet resolves `https://<host>/.well-known/did.json`.
fn did_web_host(did: &str) -> Result<&str, DidWebFault> {
    let host = did
        .strip_prefix("did:web:")
        .filter(|host| !host.is_empty())
        .ok_or(DidWebFault::NotDidWeb)?;
    if host.contains(':') || host.to_ascii_lowercase().contains("%3a") {
        return Err(DidWebFault::PortOrPath);
    }
    if !host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(DidWebFault::NotDidWeb);
    }
    Ok(host)
}

fn normalized_bind_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn is_private_metrics_address(address: IpAddr) -> bool {
    let is_private = match address {
        IpAddr::V4(address) => {
            address.is_loopback() || address.is_private() || address.is_link_local()
        }
        IpAddr::V6(address) => address.is_loopback() || address.is_unique_local(),
    };
    is_private && !address.is_unspecified() && !address.is_multicast()
}

/// The rules the service and metrics listener bindings follow.
fn binding_findings(
    listener: SocketAddr,
    metrics: Option<SocketAddr>,
    findings: &mut Vec<Finding>,
) {
    let Some(metrics) = metrics else {
        return;
    };
    if metrics.port() == 0 {
        findings.push(Finding::error(
            "evidence.oid4vp.metrics-port",
            "/metricsListener/bind",
            "the metrics listener port must be non-zero",
            "Bind the metrics listener to a fixed port the service listener does not use.",
        ));
    }
    let address = normalized_bind_address(metrics.ip());
    if !is_private_metrics_address(address) {
        findings.push(Finding::error(
            "evidence.oid4vp.metrics-address",
            "/metricsListener/bind",
            "the metrics listener must bind a loopback or private address",
            "Bind the metrics listener to a loopback, private IPv4, or unique local IPv6 address.",
        ));
    }
    let public_address = normalized_bind_address(listener.ip());
    if metrics.port() == listener.port()
        && (public_address.is_unspecified() || public_address == address)
    {
        findings.push(
            Finding::error(
                "evidence.oid4vp.metrics-shared-binding",
                "/metricsListener/bind",
                "the metrics listener must not share the service listener binding",
                "Bind the metrics listener to a port the service listener does not use.",
            )
            .reading(&["/listener/bind"]),
        );
    }
}

/// Order `diagnostics` as the shared reader orders its own: those without a
/// line first, then by line and column, keeping the order in which equal
/// positions were found.
fn in_file_order(diagnostics: &mut [Diagnostic]) {
    diagnostics.sort_by_key(|diagnostic| {
        diagnostic
            .source
            .as_ref()
            .and_then(|source| {
                source
                    .line
                    .map(|line| (1, line, source.column.unwrap_or(0)))
            })
            .unwrap_or((0, 0, 0))
    });
}

/// `finding` at the value of its member, or, for a member that is absent, at
/// the nearest mapping above it that is present.
fn positioned(check: &RuntimeFileCheck<VerifierDocument>, finding: &Finding) -> Diagnostic {
    let mut diagnostic = check.error_at(
        OID4VP_RUNTIME_KIND,
        finding.code,
        &finding.pointer,
        finding.message,
        finding.action,
    );
    diagnostic.severity = finding.severity;
    let mut located = finding.pointer.as_str();
    while diagnostic
        .source
        .as_ref()
        .is_some_and(|source| source.line.is_none())
        && !located.is_empty()
    {
        located = &located[..located.rfind('/').unwrap_or(0)];
        diagnostic.source = check
            .error_at(OID4VP_RUNTIME_KIND, "", located, "", "")
            .source;
    }
    diagnostic
}

/// Whether `finding` reads the value of a member the check left as an
/// expression, so the stand-in, not the operator's value, decided it.
fn reads_deferred_value(check: &RuntimeFileCheck<VerifierDocument>, finding: &Finding) -> bool {
    check.defers_within(&finding.pointer)
        || finding
            .reads
            .iter()
            .any(|pointer| check.defers_within(pointer))
}

/// A value for an expression the offline check does not substitute, chosen
/// so the member it fills decodes and passes the rules about its value.
fn stand_in_for(pointer: &str) -> &'static str {
    let segments: Vec<&str> = pointer.split('/').skip(1).collect();
    match segments.as_slice() {
        ["publicBaseUrl"] | ["applicantTokens" | "evidenceCredentials", "issuer"] => {
            "https://deferred.invalid"
        }
        ["listener", "bind"] => "127.0.0.1:8095",
        ["metricsListener", "bind"] => "127.0.0.1:9095",
        ["applicantTokens" | "evidenceCredentials", "algorithms", index] => {
            const ALGORITHMS: [&str; 5] = ["EdDSA", "ES256", "ES384", "RS256", "RS384"];
            ALGORITHMS[index.parse::<usize>().unwrap_or(0) % ALGORITHMS.len()]
        }
        _ => DEFAULT_STAND_IN,
    }
}
