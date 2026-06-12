// SPDX-License-Identifier: Apache-2.0
//! Stable error taxonomy and RFC 9457 Problem Details rendering.
//!
//! Every code is namespaced (`auth.*`, `filter.*`, ...) and renders as
//! an `application/problem+json` response carrying the stable string
//! in the `code` extension member alongside the standard `type`,
//! `title`, `status`, and `detail` fields. The `type` URI is built
//! from a base URL plus the code with `.` rewritten to `/`.
//!
//! ## Startup-only codes
//!
//! `config.*`, `metadata.manifest.*`, `runtime.binding.*`, and `ingest.*`
//! codes are surfaced via stderr at startup or via `/ready`'s body, never as a
//! direct response to a client request. They still implement [`IntoResponse`]
//! for defence in depth: rendering one returns `500 Internal Server Error`
//! with the correct stable code. See the per-variant [`Error::http_status`]
//! mapping for the exact status each code reports.
//!
//! ## Scrubbing
//!
//! The [`Error::detail`] method returns a short, fixed-shape human
//! message. It never embeds row data, paths, raw secrets, or stack
//! traces. Operator-supplied strings (e.g. the required scope name in
//! [`AuthError::ScopeDenied`]) are sanitised: control characters are
//! stripped and the result is truncated to a safe length so that an
//! attacker cannot smuggle newlines into the audit JSONL stream.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use registry_platform_httpsec::Problem;
use serde_json::json;
use thiserror::Error;

/// Base URL for RFC 9457 `type` URIs. Becomes configurable in V1.x;
/// pinned at compile time for V1.
pub(crate) const PROBLEM_TYPE_BASE: &str = "https://registry-relay.dev/problems/";

/// Maximum number of characters retained from an operator-supplied
/// scope name when rendered into a detail message.
const MAX_SCOPE_NAME_LEN: usize = 120;

/// Cap on the total length of a rendered detail string. Defence
/// against absurdly long operator-supplied values bloating audit
/// pipelines or response bodies.
const MAX_DETAIL_LEN: usize = 200;

/// Top-level error type spanning every namespace in the taxonomy.
#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Auth(#[from] AuthError),
    #[error("{0}")]
    Entity(#[from] EntityError),
    #[error("{0}")]
    Filter(#[from] FilterError),
    #[error("{0}")]
    Schema(#[from] SchemaError),
    #[error("{0}")]
    Ingest(#[from] IngestError),
    #[error("{0}")]
    Aggregate(#[from] AggregateError),
    #[error("{0}")]
    Admin(#[from] AdminError),
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("{0}")]
    Metadata(#[from] MetadataError),
    #[error("{0}")]
    RuntimeBinding(#[from] RuntimeBindingError),
    #[error("{0}")]
    Internal(#[from] InternalError),
    /// Provenance runtime errors.
    #[error("{0}")]
    Provenance(#[from] ProvenanceError),
    /// SP DCI request and runtime errors.
    #[error("{0}")]
    Spdci(#[from] SpdciError),
    /// OGC API Features request errors.
    #[error("{0}")]
    Ogc(#[from] OgcError),
    /// Spatial parameter and geometry errors.
    #[error("{0}")]
    Spatial(#[from] SpatialError),
    /// Query cursor and context errors.
    #[error("{0}")]
    Query(#[from] QueryError),
}

/// `entity.*` codes.
#[derive(Debug, Error)]
pub enum EntityError {
    /// Returned when a row-collection read on an entity that declares
    /// `required_filters` receives no query parameter matching any of
    /// those fields. The `required` vec carries the field names that
    /// would satisfy the requirement.
    #[error("filter required")]
    FilterRequired { required: Vec<String> },
}

/// `auth.*` codes.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing credential")]
    MissingCredential,
    #[error("invalid credential")]
    InvalidCredential,
    #[error("malformed credential")]
    MalformedCredential,
    /// `required` is the scope name from configuration. It is operator
    /// visible (not a secret) but is sanitised before being placed in
    /// the rendered detail message.
    #[error("scope denied")]
    ScopeDenied { required: String },
    #[error("purpose header required")]
    PurposeRequired,
    #[error("admin scope required")]
    AdminRequired,
    /// OIDC: the bearer JWT's `exp` is in the past (beyond the
    /// configured leeway).
    #[error("token expired")]
    TokenExpired,
    /// OIDC: the bearer JWT's `nbf` is in the future (beyond the
    /// configured leeway).
    #[error("token not yet valid")]
    TokenNotYetValid,
    /// OIDC: the bearer JWT signature did not verify against the
    /// resolved JWKS key.
    #[error("token signature invalid")]
    TokenSignatureInvalid,
    /// OIDC: the bearer JWT's `iss` does not equal the configured
    /// issuer.
    #[error("issuer mismatch")]
    IssuerMismatch,
    /// OIDC: the bearer JWT's `aud` does not intersect the configured
    /// audience set.
    #[error("audience mismatch")]
    AudienceMismatch,
    /// OIDC: the bearer JWT's `kid` is not in the JWKS document
    /// (after one rate-limited refresh).
    #[error("kid unknown")]
    KidUnknown,
    /// OIDC: the bearer JWT's `alg` is not in the configured
    /// algorithm allowlist.
    #[error("algorithm not allowed")]
    AlgorithmNotAllowed,
    /// OIDC: the bearer JWT's `azp` / `client_id` is not in the
    /// configured `allowed_clients` list.
    #[error("client not allowed")]
    ClientNotAllowed,
    /// OIDC: the configured JWKS endpoint is not reachable and the
    /// cache is empty. Mapped to 503 so operators can distinguish IdP
    /// outages from bad tokens.
    #[error("jwks unavailable")]
    JwksUnavailable,
}

/// `filter.*` codes.
#[derive(Debug, Error)]
pub enum FilterError {
    #[error("unknown field")]
    UnknownField,
    #[error("filter not allowed")]
    NotAllowed,
    #[error("unsupported operator")]
    UnsupportedOp,
    #[error("invalid filter value")]
    InvalidValue,
    #[error("too many filter values")]
    TooManyValues,
    #[error("too many filters")]
    TooManyFilters,
    #[error("invalid range")]
    InvalidRange,
    #[error("limit out of range")]
    LimitOutOfRange,
}

/// `schema.*` codes.
#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("unknown dataset")]
    UnknownDataset,
    #[error("unknown resource")]
    UnknownResource,
    #[error("unknown aggregate")]
    UnknownAggregate,
    #[error("resource unavailable")]
    ResourceUnavailable,
}

/// `ingest.*` codes. Not client-facing; surfaced via `/ready` 503 body
/// and operational logs. Rendered status falls back to 500.
#[derive(Debug, Error)]
pub enum IngestError {
    #[error("source not found")]
    SourceNotFound,
    #[error("source unreadable")]
    SourceUnreadable,
    #[error("schema mismatch")]
    SchemaMismatch,
    #[error("strict schema rejected extra column")]
    StrictExtraColumn,
    #[error("cache write failed")]
    CacheWriteFailed,
    #[error("table registration failed")]
    RegistrationFailed,
}

/// `aggregate.*` codes.
#[derive(Debug, Error)]
pub enum AggregateError {
    #[error("aggregate execution failed")]
    ExecutionFailed,
    #[error("aggregate format unsupported")]
    FormatUnsupported,
    #[error("aggregate measure unsupported")]
    MeasureUnsupported,
    #[error("disclosure violation")]
    DisclosureViolation,
    #[error("filter required")]
    FilterRequired { required: Vec<String> },
}

/// `admin.*` codes.
#[derive(Debug, Error)]
pub enum AdminError {
    #[error("reload failed")]
    ReloadFailed,
    #[error("unknown admin resource")]
    UnknownResource,
}

/// `config.*` codes. Startup-only; surfaced via stderr and a non-zero
/// process exit. Rendered status falls back to 500.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config parse error")]
    ParseError,
    #[error("config validation error")]
    ValidationError,
    #[error("missing secret")]
    MissingSecret,
    #[error("duplicate identifier in config")]
    DuplicateId,
    /// Provenance is enabled but no issuer block resolved.
    #[error("provenance issuer missing")]
    ProvenanceMissingIssuer,
    /// Gateway DID does not match the deployment host.
    #[error("provenance issuer did mismatch")]
    ProvenanceIssuerDidMismatch,
    /// Signer kind is not one of `software` or `file_watch`.
    #[error("provenance signer kind invalid")]
    ProvenanceSignerKindInvalid,
    /// Software signer's `jwk_env` is unset or empty.
    #[error("provenance jwk_env missing")]
    ProvenanceJwkEnvMissing,
    /// `signing_algorithm` is not EdDSA or ES256.
    #[error("provenance signing algorithm unsupported")]
    ProvenanceAlgorithmUnsupported,
    /// Claim validity is below 1 minute or above 365 days.
    #[error("provenance claim validity out of range")]
    ProvenanceClaimValidityOutOfRange,
    /// `context_base_url` is not a valid http(s) URL.
    #[error("provenance context base url invalid")]
    ProvenanceContextBaseUrlInvalid,
    /// `schema_base_url` is not a valid http(s) URL.
    #[error("provenance schema base url invalid")]
    ProvenanceSchemaBaseUrlInvalid,
    /// `verification_method_id` does not start with the
    /// configured issuer DID plus a fragment.
    #[error("provenance verification method mismatch")]
    ProvenanceVerificationMethodMismatch,
    /// PublicSchema CEL mapping was configured but the binary was
    /// built without the optional mapper dependency.
    #[error("publicschema cel feature disabled")]
    PublicSchemaFeatureDisabled,
    /// SP DCI standards adapters were configured but the binary was
    /// built without the optional adapter feature.
    #[error("spdci api standards feature disabled")]
    SpdciFeatureDisabled,
    /// SP DCI response CEL mapping was configured but the binary was
    /// built without the optional mapper dependency.
    #[error("spdci cel mapping feature disabled")]
    SpdciMappingFeatureDisabled,
    /// OGC API Features spatial entity config was configured but the
    /// binary was built without the optional OGC API Features surface.
    #[error("ogc api features feature disabled")]
    OgcApiFeaturesFeatureDisabled,
    /// OGC API EDR aggregate spatial config was configured but the
    /// binary was built without the optional OGC API EDR surface.
    #[error("ogc api edr feature disabled")]
    OgcApiEdrFeatureDisabled,
    /// OGC API Records conformance config was configured but the
    /// binary was built without the optional OGC API Records surface.
    #[error("ogc api records feature disabled")]
    OgcApiRecordsFeatureDisabled,
}

/// `metadata.manifest.*` startup codes for split metadata manifest loading and
/// compilation. Details stay generic; concrete parser diagnostics and paths are
/// logged at startup.
#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("metadata manifest file not found")]
    ManifestFileNotFound,
    #[error("metadata manifest parse failed")]
    ManifestParseFailed,
    #[error("metadata manifest version unsupported")]
    ManifestVersionUnsupported,
    #[error("metadata manifest validation failed")]
    ManifestValidationFailed,
    #[error("metadata manifest digest invalid")]
    ManifestDigestInvalid,
    #[error("metadata manifest digest required")]
    ManifestDigestRequired,
    #[error("metadata manifest digest mismatch")]
    ManifestDigestMismatch,
}

/// `runtime.binding.*` startup codes for runtime config references into the
/// compiled portable metadata manifest.
#[derive(Debug, Error)]
pub enum RuntimeBindingError {
    #[error("runtime dataset missing from metadata")]
    DatasetMissing,
    #[error("runtime entity missing from metadata")]
    EntityMissing,
    #[error("runtime table missing")]
    TableMissing,
    #[error("runtime field missing from metadata")]
    FieldMissing,
    #[error("runtime filter missing from metadata")]
    FilterMissing,
    #[error("runtime scope missing or invalid")]
    ScopeMissing,
    #[error("runtime relationship missing from metadata")]
    RelationshipMissing,
    #[error("runtime evidence offering kind is unsupported")]
    UnsupportedEvidenceOffering,
}

/// `provenance.*` runtime codes.
#[derive(Debug, Error)]
pub enum ProvenanceError {
    /// The signer is configured but unavailable at request time (e.g.
    /// KMS outage). Surfaces as `503` when `Accept` requested only a
    /// provenance media type.
    #[error("provenance signer unavailable")]
    SignerUnavailable,
    /// Building the VC payload or compact JWS failed for an internal
    /// reason. Generic 500 with a stable code; details land in logs.
    #[error("provenance issuance failed")]
    IssuanceFailed,
    /// Requested claim type or version is not registered (used by
    /// `/schemas/{type}/{version}.json` and contexts route).
    #[error("provenance unknown claim type or version")]
    UnknownResource,
    /// `/.well-known/did.json` is not served in delegated mode.
    #[error("provenance did document unavailable")]
    DidDocumentUnavailable,
}

/// `spdci.*` runtime codes. Cover request envelope validation against
/// the SP DCI standard (header + message) and wiring invariants for
/// the response mapper extension.
#[derive(Debug, Error)]
pub enum SpdciError {
    /// `header` is missing or not an object, or one of the required
    /// header fields (`message_id`, `message_ts`, `action`, `sender_id`,
    /// `total_count`) is absent.
    #[error("invalid spdci header")]
    InvalidHeader,
    /// `message` is missing or not an object.
    #[error("invalid spdci message")]
    InvalidMessage,
    /// `message.transaction_id` is absent or empty.
    #[error("missing transaction_id")]
    MissingTransactionId,
    /// The registry has SP DCI response mapping configured but the
    /// `SpdciResponseMapper` extension was not installed on the router.
    /// Surfaced as 500 because it is a binary wiring bug.
    #[error("spdci response mapper unavailable")]
    MapperUnavailable,
}

/// `ogc.*` runtime codes.
#[derive(Debug, Error)]
pub enum OgcError {
    /// Dataset or collection does not exist, is not spatially exposed,
    /// or is not visible to the caller.
    #[error("ogc collection not found")]
    CollectionNotFound,
    /// Feature does not exist, is not visible, or does not match the
    /// filter context required by the collection policy.
    #[error("ogc feature not found")]
    FeatureNotFound,
    /// Record does not exist or is not visible to the caller.
    #[error("ogc record not found")]
    RecordNotFound,
}

/// `spatial.*` runtime codes.
#[derive(Debug, Error)]
pub enum SpatialError {
    /// Geometry value is malformed at runtime.
    #[error("spatial geometry invalid")]
    GeometryInvalid,
    /// Geometry exceeds the configured vertex cap.
    #[error("spatial geometry too large")]
    GeometryTooLarge,
    /// Bbox parameter is malformed.
    #[error("spatial bbox invalid")]
    BboxInvalid,
    /// Bbox crosses the antimeridian. Phase 1 rejects these with the
    /// same stable code as other invalid bbox shapes, but a clearer
    /// client-facing detail.
    #[error("spatial bbox crosses antimeridian")]
    BboxAntimeridianUnsupported,
    /// A supported parameter name cannot be evaluated for this
    /// collection. `parameter` is client-visible and sanitized before
    /// rendering.
    #[error("spatial filter unsupported")]
    FilterUnsupported { parameter: String },
    /// Requested CRS is not supported by Phase 1 OGC routes.
    #[error("spatial crs unsupported")]
    CrsUnsupported,
}

/// `query.*` runtime codes.
#[derive(Debug, Error)]
pub enum QueryError {
    /// Cursor is malformed, expired, or bound to a different query
    /// context, principal, collection, or filter set.
    #[error("query cursor invalid")]
    CursorInvalid,
}

/// `internal.*` codes.
#[derive(Debug, Error)]
pub enum InternalError {
    #[error("request timed out")]
    Timeout,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("uri too long")]
    UriTooLong,
    #[error("unhandled internal error")]
    Unhandled,
}

impl Error {
    /// Stable string code published in audit `error_code` fields and
    /// in the Problem Details `code` extension member.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Error::Auth(e) => e.code(),
            Error::Entity(e) => e.code(),
            Error::Filter(e) => e.code(),
            Error::Schema(e) => e.code(),
            Error::Ingest(e) => e.code(),
            Error::Aggregate(e) => e.code(),
            Error::Admin(e) => e.code(),
            Error::Config(e) => e.code(),
            Error::Metadata(e) => e.code(),
            Error::RuntimeBinding(e) => e.code(),
            Error::Internal(e) => e.code(),
            Error::Provenance(e) => e.code(),
            Error::Spdci(e) => e.code(),
            Error::Ogc(e) => e.code(),
            Error::Spatial(e) => e.code(),
            Error::Query(e) => e.code(),
        }
    }

    /// HTTP status to return when this error reaches the wire.
    ///
    /// Startup-only variants (every `config.*` and `ingest.*` code)
    /// return [`StatusCode::INTERNAL_SERVER_ERROR`]; they should never
    /// be rendered to a client in practice, but the function is total
    /// so the [`IntoResponse`] impl always has a status.
    #[must_use]
    pub fn http_status(&self) -> StatusCode {
        match self {
            Error::Auth(e) => e.http_status(),
            Error::Entity(e) => e.http_status(),
            Error::Filter(e) => e.http_status(),
            Error::Schema(e) => e.http_status(),
            Error::Ingest(e) => e.http_status(),
            Error::Aggregate(e) => e.http_status(),
            Error::Admin(e) => e.http_status(),
            Error::Config(e) => e.http_status(),
            Error::Metadata(e) => e.http_status(),
            Error::RuntimeBinding(e) => e.http_status(),
            Error::Internal(e) => e.http_status(),
            Error::Provenance(e) => e.http_status(),
            Error::Spdci(e) => e.http_status(),
            Error::Ogc(e) => e.http_status(),
            Error::Spatial(e) => e.http_status(),
            Error::Query(e) => e.http_status(),
        }
    }

    /// Short human-readable title for the Problem Details `title`
    /// field. Fixed string per variant; never includes user data.
    #[must_use]
    pub fn title(&self) -> &'static str {
        match self {
            Error::Auth(e) => e.title(),
            Error::Entity(e) => e.title(),
            Error::Filter(e) => e.title(),
            Error::Schema(e) => e.title(),
            Error::Ingest(e) => e.title(),
            Error::Aggregate(e) => e.title(),
            Error::Admin(e) => e.title(),
            Error::Config(e) => e.title(),
            Error::Metadata(e) => e.title(),
            Error::RuntimeBinding(e) => e.title(),
            Error::Internal(e) => e.title(),
            Error::Provenance(e) => e.title(),
            Error::Spdci(e) => e.title(),
            Error::Ogc(e) => e.title(),
            Error::Spatial(e) => e.title(),
            Error::Query(e) => e.title(),
        }
    }

    /// Short scrubbed human message for the Problem Details `detail`
    /// field. Never contains paths, secrets, stack traces, or row
    /// data. Operator-supplied strings (e.g. scope names) are
    /// sanitised and length-capped.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Error::Auth(e) => e.detail(),
            Error::Entity(e) => e.detail(),
            Error::Filter(e) => e.detail().to_string(),
            Error::Schema(e) => e.detail().to_string(),
            Error::Ingest(e) => e.detail().to_string(),
            Error::Aggregate(e) => e.detail().to_string(),
            Error::Admin(e) => e.detail().to_string(),
            Error::Config(e) => e.detail().to_string(),
            Error::Metadata(e) => e.detail().to_string(),
            Error::RuntimeBinding(e) => e.detail().to_string(),
            Error::Internal(e) => e.detail().to_string(),
            Error::Provenance(e) => e.detail().to_string(),
            Error::Spdci(e) => e.detail().to_string(),
            Error::Ogc(e) => e.detail().to_string(),
            Error::Spatial(e) => e.detail(),
            Error::Query(e) => e.detail().to_string(),
        }
    }

    /// Build the RFC 9457 `type` URI for this error's stable code.
    fn type_uri(&self) -> String {
        let path = self.code().replace('.', "/");
        format!("{PROBLEM_TYPE_BASE}{path}")
    }

    /// Render the error as a shared platform [`Problem`] with all required
    /// RFC 9457 fields and the stable `code` extension.
    fn to_problem(&self) -> Problem {
        let problem = Problem::new(&self.type_uri(), self.title(), self.http_status())
            .detail(self.detail())
            .with_extra("code", json!(self.code()));
        match self {
            Error::Spatial(SpatialError::FilterUnsupported { parameter }) => problem.with_extra(
                "parameter",
                json!(sanitise_operator_string(parameter, MAX_SCOPE_NAME_LEN)),
            ),
            _ => problem,
        }
    }
}

impl EntityError {
    fn code(&self) -> &'static str {
        match self {
            EntityError::FilterRequired { .. } => "entity.filter_required",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            EntityError::FilterRequired { .. } => StatusCode::BAD_REQUEST,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            EntityError::FilterRequired { .. } => "Filter required",
        }
    }

    fn detail(&self) -> String {
        match self {
            EntityError::FilterRequired { required } => {
                let fields = required.join(", ");
                truncate(format!("one of: {fields}"), MAX_DETAIL_LEN)
            }
        }
    }
}

impl AuthError {
    fn code(&self) -> &'static str {
        match self {
            AuthError::MissingCredential => "auth.missing_credential",
            AuthError::InvalidCredential => "auth.invalid_credential",
            AuthError::MalformedCredential => "auth.malformed_credential",
            AuthError::ScopeDenied { .. } => "auth.scope_denied",
            AuthError::PurposeRequired => "auth.purpose_required",
            AuthError::AdminRequired => "auth.admin_required",
            AuthError::TokenExpired => "auth.token_expired",
            AuthError::TokenNotYetValid => "auth.token_not_yet_valid",
            AuthError::TokenSignatureInvalid => "auth.token_signature_invalid",
            AuthError::IssuerMismatch => "auth.issuer_mismatch",
            AuthError::AudienceMismatch => "auth.audience_mismatch",
            AuthError::KidUnknown => "auth.kid_unknown",
            AuthError::AlgorithmNotAllowed => "auth.algorithm_not_allowed",
            AuthError::ClientNotAllowed => "auth.client_not_allowed",
            AuthError::JwksUnavailable => "auth.jwks_unavailable",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            AuthError::MissingCredential
            | AuthError::InvalidCredential
            | AuthError::MalformedCredential
            | AuthError::TokenExpired
            | AuthError::TokenNotYetValid
            | AuthError::TokenSignatureInvalid
            | AuthError::IssuerMismatch
            | AuthError::AudienceMismatch
            | AuthError::KidUnknown
            | AuthError::AlgorithmNotAllowed => StatusCode::UNAUTHORIZED,
            AuthError::ScopeDenied { .. }
            | AuthError::AdminRequired
            | AuthError::ClientNotAllowed => StatusCode::FORBIDDEN,
            AuthError::PurposeRequired => StatusCode::BAD_REQUEST,
            AuthError::JwksUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            AuthError::MissingCredential => "Missing credential",
            AuthError::InvalidCredential => "Invalid credential",
            AuthError::MalformedCredential => "Malformed credential",
            AuthError::ScopeDenied { .. } => "Scope denied",
            AuthError::PurposeRequired => "Purpose header required",
            AuthError::AdminRequired => "Admin scope required",
            AuthError::TokenExpired => "Token expired",
            AuthError::TokenNotYetValid => "Token not yet valid",
            AuthError::TokenSignatureInvalid => "Token signature invalid",
            AuthError::IssuerMismatch => "Issuer mismatch",
            AuthError::AudienceMismatch => "Audience mismatch",
            AuthError::KidUnknown => "Unknown signing key",
            AuthError::AlgorithmNotAllowed => "Algorithm not allowed",
            AuthError::ClientNotAllowed => "Client not allowed",
            AuthError::JwksUnavailable => "JWKS unavailable",
        }
    }

    fn detail(&self) -> String {
        match self {
            AuthError::MissingCredential => {
                "no credential provided in Authorization or x-api-key header".to_string()
            }
            AuthError::InvalidCredential => {
                "credential did not match any configured key".to_string()
            }
            AuthError::MalformedCredential => "credential header was not parseable".to_string(),
            AuthError::ScopeDenied { required } => {
                let safe = sanitise_operator_string(required, MAX_SCOPE_NAME_LEN);
                truncate(format!("required scope: {safe}"), MAX_DETAIL_LEN)
            }
            AuthError::PurposeRequired => {
                "Data-Purpose header is required for this resource".to_string()
            }
            AuthError::AdminRequired => "admin scope is required for this endpoint".to_string(),
            AuthError::TokenExpired => "bearer token has expired".to_string(),
            AuthError::TokenNotYetValid => "bearer token is not yet valid".to_string(),
            AuthError::TokenSignatureInvalid => "bearer token signature did not verify".to_string(),
            AuthError::IssuerMismatch => {
                "bearer token issuer does not match the configured issuer".to_string()
            }
            AuthError::AudienceMismatch => {
                "bearer token audience does not match the configured audience".to_string()
            }
            AuthError::KidUnknown => "bearer token key id is not in the JWKS document".to_string(),
            AuthError::AlgorithmNotAllowed => {
                "bearer token algorithm is not in the configured allowlist".to_string()
            }
            AuthError::ClientNotAllowed => {
                "bearer token client is not in the configured allowed_clients list".to_string()
            }
            AuthError::JwksUnavailable => {
                "the JWKS endpoint is unreachable and no cached keys are available".to_string()
            }
        }
    }
}

impl FilterError {
    fn code(&self) -> &'static str {
        match self {
            FilterError::UnknownField => "filter.unknown_field",
            FilterError::NotAllowed => "filter.not_allowed",
            FilterError::UnsupportedOp => "filter.unsupported_op",
            FilterError::InvalidValue => "filter.invalid_value",
            FilterError::TooManyValues => "filter.too_many_values",
            FilterError::TooManyFilters => "filter.too_many_filters",
            FilterError::InvalidRange => "filter.invalid_range",
            FilterError::LimitOutOfRange => "filter.limit_out_of_range",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            // Spec §7.bis.5 maps "filter value list exceeds the
            // configured cap" to 413. All other filter.* codes are
            // client-side 400 (unknown field, parser error, etc.).
            FilterError::TooManyValues => StatusCode::PAYLOAD_TOO_LARGE,
            FilterError::UnknownField
            | FilterError::NotAllowed
            | FilterError::UnsupportedOp
            | FilterError::InvalidValue
            | FilterError::TooManyFilters
            | FilterError::InvalidRange
            | FilterError::LimitOutOfRange => StatusCode::BAD_REQUEST,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            FilterError::UnknownField => "Unknown filter field",
            FilterError::NotAllowed => "Filter not allowed",
            FilterError::UnsupportedOp => "Unsupported filter operator",
            FilterError::InvalidValue => "Invalid filter value",
            FilterError::TooManyValues => "Too many filter values",
            FilterError::TooManyFilters => "Too many filters",
            FilterError::InvalidRange => "Invalid range",
            FilterError::LimitOutOfRange => "Limit out of range",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            FilterError::UnknownField => {
                "query parameter references a field not in the resource schema"
            }
            FilterError::NotAllowed => "field is not in the resource's allowed_filters list",
            FilterError::UnsupportedOp => "operator is not allowed for this field",
            FilterError::InvalidValue => "value does not parse for the field's type",
            FilterError::TooManyValues => "in-list exceeds the configured maximum of 100 values",
            FilterError::TooManyFilters => {
                "request carries more filter parameters than the per-request cap allows"
            }
            FilterError::InvalidRange => "range bounds are inverted or invalid",
            FilterError::LimitOutOfRange => {
                "limit exceeds the configured max_limit or is non-positive"
            }
        }
    }
}

impl SchemaError {
    fn code(&self) -> &'static str {
        match self {
            SchemaError::UnknownDataset => "schema.unknown_dataset",
            SchemaError::UnknownResource => "schema.unknown_resource",
            SchemaError::UnknownAggregate => "schema.unknown_aggregate",
            SchemaError::ResourceUnavailable => "schema.resource_unavailable",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            SchemaError::UnknownDataset
            | SchemaError::UnknownResource
            | SchemaError::UnknownAggregate => StatusCode::NOT_FOUND,
            SchemaError::ResourceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            SchemaError::UnknownDataset => "Unknown dataset",
            SchemaError::UnknownResource => "Unknown resource",
            SchemaError::UnknownAggregate => "Unknown aggregate",
            SchemaError::ResourceUnavailable => "Resource unavailable",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            SchemaError::UnknownDataset => "dataset id is not registered",
            SchemaError::UnknownResource => "resource id is not registered under the dataset",
            SchemaError::UnknownAggregate => "aggregate id is not declared for the resource",
            SchemaError::ResourceUnavailable => {
                "resource is configured but failed ingest or is mid-reload"
            }
        }
    }
}

impl IngestError {
    fn code(&self) -> &'static str {
        match self {
            IngestError::SourceNotFound => "ingest.source_not_found",
            IngestError::SourceUnreadable => "ingest.source_unreadable",
            IngestError::SchemaMismatch => "ingest.schema_mismatch",
            IngestError::StrictExtraColumn => "ingest.strict_extra_column",
            IngestError::CacheWriteFailed => "ingest.cache_write_failed",
            IngestError::RegistrationFailed => "ingest.registration_failed",
        }
    }

    fn http_status(&self) -> StatusCode {
        // Startup-only; fallback to 500 if ever rendered.
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn title(&self) -> &'static str {
        match self {
            IngestError::SourceNotFound => "Source not found",
            IngestError::SourceUnreadable => "Source unreadable",
            IngestError::SchemaMismatch => "Schema mismatch",
            IngestError::StrictExtraColumn => "Strict schema rejected extra column",
            IngestError::CacheWriteFailed => "Cache write failed",
            IngestError::RegistrationFailed => "Table registration failed",
        }
    }

    fn detail(&self) -> &'static str {
        // No file paths or row data; detail is generic so it is safe
        // to surface in `/ready` bodies and operational logs.
        match self {
            IngestError::SourceNotFound => "configured source is missing or unreadable",
            IngestError::SourceUnreadable => "source could not be read or parsed",
            IngestError::SchemaMismatch => {
                "declared schema does not match observed columns or types"
            }
            IngestError::StrictExtraColumn => "source contains columns absent from a strict schema",
            IngestError::CacheWriteFailed => "parquet cache could not be written",
            IngestError::RegistrationFailed => "DataFusion table registration failed",
        }
    }
}

impl AggregateError {
    fn code(&self) -> &'static str {
        match self {
            AggregateError::ExecutionFailed => "aggregate.execution_failed",
            AggregateError::FormatUnsupported => "aggregate.format_unsupported",
            AggregateError::MeasureUnsupported => "aggregate.measure_unsupported",
            AggregateError::DisclosureViolation => "aggregate.disclosure_violation",
            AggregateError::FilterRequired { .. } => "aggregate.filter_required",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            AggregateError::FilterRequired { .. } | AggregateError::FormatUnsupported => {
                StatusCode::BAD_REQUEST
            }
            AggregateError::ExecutionFailed
            | AggregateError::MeasureUnsupported
            | AggregateError::DisclosureViolation => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            AggregateError::ExecutionFailed => "Aggregate execution failed",
            AggregateError::FormatUnsupported => "Aggregate format unsupported",
            AggregateError::MeasureUnsupported => "Aggregate measure unsupported",
            AggregateError::DisclosureViolation => "Disclosure violation",
            AggregateError::FilterRequired { .. } => "Filter required",
        }
    }

    fn detail(&self) -> String {
        match self {
            AggregateError::ExecutionFailed => {
                "query engine returned an execution error".to_string()
            }
            AggregateError::FormatUnsupported => {
                "requested aggregate response format is not supported".to_string()
            }
            AggregateError::MeasureUnsupported => {
                "configured measure references a function that is not implemented".to_string()
            }
            // Note: this is an internal invariant violation. The
            // string is deliberately generic; nothing about the
            // offending group reaches the client.
            AggregateError::DisclosureViolation => {
                "disclosure-control invariant was violated before response".to_string()
            }
            AggregateError::FilterRequired { required } => {
                let fields = required.join(", ");
                truncate(format!("one of: {fields}"), MAX_DETAIL_LEN)
            }
        }
    }
}

impl AdminError {
    fn code(&self) -> &'static str {
        match self {
            AdminError::ReloadFailed => "admin.reload_failed",
            AdminError::UnknownResource => "admin.unknown_resource",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            AdminError::ReloadFailed => StatusCode::INTERNAL_SERVER_ERROR,
            AdminError::UnknownResource => StatusCode::NOT_FOUND,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            AdminError::ReloadFailed => "Reload failed",
            AdminError::UnknownResource => "Unknown admin resource",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            AdminError::ReloadFailed => "one or more resources failed to reload",
            AdminError::UnknownResource => "reload target id was not found",
        }
    }
}

impl ConfigError {
    fn code(&self) -> &'static str {
        match self {
            ConfigError::ParseError => "config.parse_error",
            ConfigError::ValidationError => "config.validation_error",
            ConfigError::MissingSecret => "config.missing_secret",
            ConfigError::DuplicateId => "config.duplicate_id",
            ConfigError::ProvenanceMissingIssuer => "provenance.config.missing_issuer",
            ConfigError::ProvenanceIssuerDidMismatch => "provenance.config.issuer_did_mismatch",
            ConfigError::ProvenanceSignerKindInvalid => "provenance.config.signer_kind_invalid",
            ConfigError::ProvenanceJwkEnvMissing => "provenance.config.jwk_env_missing",
            ConfigError::ProvenanceAlgorithmUnsupported => {
                "provenance.config.algorithm_unsupported"
            }
            ConfigError::ProvenanceClaimValidityOutOfRange => {
                "provenance.config.claim_validity_out_of_range"
            }
            ConfigError::ProvenanceContextBaseUrlInvalid => {
                "provenance.config.context_base_url_invalid"
            }
            ConfigError::ProvenanceSchemaBaseUrlInvalid => {
                "provenance.config.schema_base_url_invalid"
            }
            ConfigError::ProvenanceVerificationMethodMismatch => {
                "provenance.config.verification_method_mismatch"
            }
            ConfigError::PublicSchemaFeatureDisabled => "publicschema.config.feature_disabled",
            ConfigError::SpdciFeatureDisabled => "spdci.config.feature_disabled",
            ConfigError::SpdciMappingFeatureDisabled => "spdci.config.mapping_feature_disabled",
            ConfigError::OgcApiFeaturesFeatureDisabled => "ogcapi.features.config.feature_disabled",
            ConfigError::OgcApiEdrFeatureDisabled => "ogcapi.edr.config.feature_disabled",
            ConfigError::OgcApiRecordsFeatureDisabled => "ogcapi.records.config.feature_disabled",
        }
    }

    fn http_status(&self) -> StatusCode {
        // Startup-only; fallback to 500 if ever rendered.
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn title(&self) -> &'static str {
        match self {
            ConfigError::ParseError => "Config parse error",
            ConfigError::ValidationError => "Config validation error",
            // Avoid the literal word "secret" in operator-facing
            // strings; the stable taxonomy code retains it.
            ConfigError::MissingSecret => "Missing credential hash",
            ConfigError::DuplicateId => "Duplicate identifier",
            ConfigError::ProvenanceMissingIssuer => "Provenance issuer missing",
            ConfigError::ProvenanceIssuerDidMismatch => "Provenance issuer DID mismatch",
            ConfigError::ProvenanceSignerKindInvalid => "Provenance signer kind invalid",
            ConfigError::ProvenanceJwkEnvMissing => "Provenance signing key unavailable",
            ConfigError::ProvenanceAlgorithmUnsupported => "Provenance algorithm unsupported",
            ConfigError::ProvenanceClaimValidityOutOfRange => "Provenance claim validity invalid",
            ConfigError::ProvenanceContextBaseUrlInvalid => "Provenance context base URL invalid",
            ConfigError::ProvenanceSchemaBaseUrlInvalid => "Provenance schema base URL invalid",
            ConfigError::ProvenanceVerificationMethodMismatch => {
                "Provenance verification method mismatch"
            }
            ConfigError::PublicSchemaFeatureDisabled => "PublicSchema CEL feature disabled",
            ConfigError::SpdciFeatureDisabled => "SP DCI API standards feature disabled",
            ConfigError::SpdciMappingFeatureDisabled => "SP DCI CEL mapping feature disabled",
            ConfigError::OgcApiFeaturesFeatureDisabled => "OGC API Features feature disabled",
            ConfigError::OgcApiEdrFeatureDisabled => "OGC API EDR feature disabled",
            ConfigError::OgcApiRecordsFeatureDisabled => "OGC API Records feature disabled",
        }
    }

    fn detail(&self) -> &'static str {
        // Generic strings only: env var names, file paths, and YAML
        // line numbers belong on stderr, not in any response body.
        match self {
            ConfigError::ParseError => "configuration document did not deserialize",
            ConfigError::ValidationError => "configuration failed cross-field validation",
            ConfigError::MissingSecret => "a required hash environment variable is unset",
            ConfigError::DuplicateId => "two configured ids collide",
            ConfigError::ProvenanceMissingIssuer => {
                "provenance is enabled but no issuer block resolved"
            }
            ConfigError::ProvenanceIssuerDidMismatch => {
                "configured issuer DID does not match the deployment host"
            }
            ConfigError::ProvenanceSignerKindInvalid => {
                "signer kind must be software or file_watch"
            }
            ConfigError::ProvenanceJwkEnvMissing => {
                "the configured signing key material is unavailable"
            }
            ConfigError::ProvenanceAlgorithmUnsupported => {
                "signing_algorithm must be EdDSA or ES256"
            }
            ConfigError::ProvenanceClaimValidityOutOfRange => {
                "claim validity must be between 1 minute and 365 days"
            }
            ConfigError::ProvenanceContextBaseUrlInvalid => {
                "context_base_url must be a syntactically valid http(s) URL"
            }
            ConfigError::ProvenanceSchemaBaseUrlInvalid => {
                "schema_base_url must be a syntactically valid http(s) URL"
            }
            ConfigError::ProvenanceVerificationMethodMismatch => {
                "verification_method_id must be a fragment of the issuer DID"
            }
            ConfigError::PublicSchemaFeatureDisabled => {
                "publicschema mappings require a binary built with the publicschema-cel feature"
            }
            ConfigError::SpdciFeatureDisabled => {
                "SP DCI standards adapters require a binary built with the spdci-api-standards feature"
            }
            ConfigError::SpdciMappingFeatureDisabled => {
                "SP DCI response mappings require a binary built with the standards-cel-mapping feature"
            }
            ConfigError::OgcApiFeaturesFeatureDisabled => {
                "OGC API Features spatial config requires a binary built with the ogcapi-features feature"
            }
            ConfigError::OgcApiEdrFeatureDisabled => {
                "OGC API EDR aggregate spatial config requires a binary built with the ogcapi-edr feature"
            }
            ConfigError::OgcApiRecordsFeatureDisabled => {
                "OGC API Records conformance config requires a binary built with the ogcapi-records feature"
            }
        }
    }
}

impl MetadataError {
    fn code(&self) -> &'static str {
        match self {
            MetadataError::ManifestFileNotFound => "metadata.manifest.file_not_found",
            MetadataError::ManifestParseFailed => "metadata.manifest.parse_failed",
            MetadataError::ManifestVersionUnsupported => "metadata.manifest.version_unsupported",
            MetadataError::ManifestValidationFailed => "metadata.manifest.validation_failed",
            MetadataError::ManifestDigestInvalid => "metadata.manifest.digest_invalid",
            MetadataError::ManifestDigestRequired => "metadata.manifest.digest_required",
            MetadataError::ManifestDigestMismatch => "metadata.manifest.digest_mismatch",
        }
    }

    fn http_status(&self) -> StatusCode {
        // Startup-only; fallback to 500 if ever rendered.
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn title(&self) -> &'static str {
        match self {
            MetadataError::ManifestFileNotFound => "Metadata manifest file not found",
            MetadataError::ManifestParseFailed => "Metadata manifest parse failed",
            MetadataError::ManifestVersionUnsupported => "Metadata manifest version unsupported",
            MetadataError::ManifestValidationFailed => "Metadata manifest validation failed",
            MetadataError::ManifestDigestInvalid => "Metadata manifest digest invalid",
            MetadataError::ManifestDigestRequired => "Metadata manifest digest required",
            MetadataError::ManifestDigestMismatch => "Metadata manifest digest mismatch",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            MetadataError::ManifestFileNotFound => "metadata manifest could not be read",
            MetadataError::ManifestParseFailed => "metadata manifest did not deserialize",
            MetadataError::ManifestVersionUnsupported => {
                "metadata manifest schema_version is not supported"
            }
            MetadataError::ManifestValidationFailed => {
                "metadata manifest failed semantic validation"
            }
            MetadataError::ManifestDigestInvalid => "metadata manifest digest is not valid",
            MetadataError::ManifestDigestRequired => {
                "governed configuration requires metadata manifest digest"
            }
            MetadataError::ManifestDigestMismatch => {
                "metadata manifest digest did not match configured digest"
            }
        }
    }
}

impl RuntimeBindingError {
    fn code(&self) -> &'static str {
        match self {
            RuntimeBindingError::DatasetMissing => "runtime.binding.dataset_missing",
            RuntimeBindingError::EntityMissing => "runtime.binding.entity_missing",
            RuntimeBindingError::TableMissing => "runtime.binding.table_missing",
            RuntimeBindingError::FieldMissing => "runtime.binding.field_missing",
            RuntimeBindingError::FilterMissing => "runtime.binding.filter_missing",
            RuntimeBindingError::ScopeMissing => "runtime.binding.scope_missing",
            RuntimeBindingError::RelationshipMissing => "runtime.binding.relationship_missing",
            RuntimeBindingError::UnsupportedEvidenceOffering => {
                "runtime.binding.unsupported_evidence_offering"
            }
        }
    }

    fn http_status(&self) -> StatusCode {
        // Startup-only; fallback to 500 if ever rendered.
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn title(&self) -> &'static str {
        match self {
            RuntimeBindingError::DatasetMissing => "Runtime dataset missing from metadata",
            RuntimeBindingError::EntityMissing => "Runtime entity missing from metadata",
            RuntimeBindingError::TableMissing => "Runtime table missing",
            RuntimeBindingError::FieldMissing => "Runtime field missing from metadata",
            RuntimeBindingError::FilterMissing => "Runtime filter missing from metadata",
            RuntimeBindingError::ScopeMissing => "Runtime scope missing or invalid",
            RuntimeBindingError::RelationshipMissing => {
                "Runtime relationship missing from metadata"
            }
            RuntimeBindingError::UnsupportedEvidenceOffering => "Unsupported evidence offering",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            RuntimeBindingError::DatasetMissing => {
                "runtime dataset id is absent from the metadata manifest"
            }
            RuntimeBindingError::EntityMissing => {
                "runtime entity name is absent from the metadata manifest"
            }
            RuntimeBindingError::TableMissing => {
                "runtime entity references a table that is not configured"
            }
            RuntimeBindingError::FieldMissing => {
                "runtime field binding is absent from the metadata manifest"
            }
            RuntimeBindingError::FilterMissing => {
                "runtime filter binding is absent from the metadata manifest"
            }
            RuntimeBindingError::ScopeMissing => {
                "runtime scope is missing or does not use a supported scope shape"
            }
            RuntimeBindingError::RelationshipMissing => {
                "runtime relationship binding is absent from the metadata manifest"
            }
            RuntimeBindingError::UnsupportedEvidenceOffering => {
                "only external Registry Notary evidence offerings are supported"
            }
        }
    }
}

impl ProvenanceError {
    fn code(&self) -> &'static str {
        match self {
            ProvenanceError::SignerUnavailable => "provenance.signer_unavailable",
            ProvenanceError::IssuanceFailed => "provenance.issuance_failed",
            ProvenanceError::UnknownResource => "provenance.unknown_resource",
            ProvenanceError::DidDocumentUnavailable => "provenance.did_document_unavailable",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            ProvenanceError::SignerUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ProvenanceError::IssuanceFailed => StatusCode::INTERNAL_SERVER_ERROR,
            ProvenanceError::UnknownResource | ProvenanceError::DidDocumentUnavailable => {
                StatusCode::NOT_FOUND
            }
        }
    }

    fn title(&self) -> &'static str {
        match self {
            ProvenanceError::SignerUnavailable => "Signer unavailable",
            ProvenanceError::IssuanceFailed => "Provenance issuance failed",
            ProvenanceError::UnknownResource => "Unknown provenance resource",
            ProvenanceError::DidDocumentUnavailable => "DID document unavailable",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            ProvenanceError::SignerUnavailable => {
                "the configured signing backend is not currently available"
            }
            ProvenanceError::IssuanceFailed => {
                "the request could not be served as a verifiable credential"
            }
            ProvenanceError::UnknownResource => {
                "no resource is registered for the requested claim type or version"
            }
            ProvenanceError::DidDocumentUnavailable => {
                "this deployment does not host a did:web document"
            }
        }
    }
}

impl InternalError {
    fn code(&self) -> &'static str {
        match self {
            InternalError::Timeout => "internal.timeout",
            InternalError::PayloadTooLarge => "internal.payload_too_large",
            InternalError::UriTooLong => "internal.uri_too_long",
            InternalError::Unhandled => "internal.unhandled",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            InternalError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            InternalError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            InternalError::UriTooLong => StatusCode::URI_TOO_LONG,
            InternalError::Unhandled => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            InternalError::Timeout => "Request timed out",
            InternalError::PayloadTooLarge => "Payload too large",
            InternalError::UriTooLong => "URI too long",
            InternalError::Unhandled => "Internal server error",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            InternalError::Timeout => "request exceeded the configured timeout",
            InternalError::PayloadTooLarge => {
                "request body or response cardinality exceeds configured caps"
            }
            InternalError::UriTooLong => {
                "request URI (path plus query string) exceeds the configured length cap"
            }
            InternalError::Unhandled => "the request could not be served",
        }
    }
}

impl SpdciError {
    fn code(&self) -> &'static str {
        match self {
            SpdciError::InvalidHeader => "spdci.request.invalid_header",
            SpdciError::InvalidMessage => "spdci.request.invalid_message",
            SpdciError::MissingTransactionId => "spdci.request.missing_transaction_id",
            SpdciError::MapperUnavailable => "spdci.mapper.unavailable",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            SpdciError::InvalidHeader
            | SpdciError::InvalidMessage
            | SpdciError::MissingTransactionId => StatusCode::BAD_REQUEST,
            SpdciError::MapperUnavailable => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            SpdciError::InvalidHeader => "Invalid SP DCI header",
            SpdciError::InvalidMessage => "Invalid SP DCI message",
            SpdciError::MissingTransactionId => "Missing transaction_id",
            SpdciError::MapperUnavailable => "SP DCI response mapper unavailable",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            SpdciError::InvalidHeader => {
                "request header is missing or omits a required SP DCI field"
            }
            SpdciError::InvalidMessage => "request message is missing or not an object",
            SpdciError::MissingTransactionId => {
                "message.transaction_id is required and must be non-empty"
            }
            SpdciError::MapperUnavailable => {
                "response mapping is configured but the mapper extension is not installed"
            }
        }
    }
}

impl OgcError {
    fn code(&self) -> &'static str {
        match self {
            OgcError::CollectionNotFound => "ogc.collection_not_found",
            OgcError::FeatureNotFound => "ogc.feature_not_found",
            OgcError::RecordNotFound => "ogc.record_not_found",
        }
    }

    fn http_status(&self) -> StatusCode {
        StatusCode::NOT_FOUND
    }

    fn title(&self) -> &'static str {
        match self {
            OgcError::CollectionNotFound => "OGC collection not found",
            OgcError::FeatureNotFound => "OGC feature not found",
            OgcError::RecordNotFound => "OGC record not found",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            OgcError::CollectionNotFound => {
                "collection is not registered, spatially exposed, or visible to the caller"
            }
            OgcError::FeatureNotFound => {
                "feature is not registered, visible, or within the required filter context"
            }
            OgcError::RecordNotFound => "record is not registered or visible to the caller",
        }
    }
}

impl SpatialError {
    fn code(&self) -> &'static str {
        match self {
            SpatialError::GeometryInvalid => "spatial.geometry_invalid",
            SpatialError::GeometryTooLarge => "spatial.geometry_too_large",
            SpatialError::BboxInvalid | SpatialError::BboxAntimeridianUnsupported => {
                "spatial.bbox_invalid"
            }
            SpatialError::FilterUnsupported { .. } => "spatial.filter_unsupported",
            SpatialError::CrsUnsupported => "spatial.crs_unsupported",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            SpatialError::GeometryInvalid => StatusCode::INTERNAL_SERVER_ERROR,
            SpatialError::GeometryTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            SpatialError::BboxInvalid
            | SpatialError::BboxAntimeridianUnsupported
            | SpatialError::FilterUnsupported { .. }
            | SpatialError::CrsUnsupported => StatusCode::BAD_REQUEST,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            SpatialError::GeometryInvalid => "Spatial geometry invalid",
            SpatialError::GeometryTooLarge => "Spatial geometry too large",
            SpatialError::BboxInvalid | SpatialError::BboxAntimeridianUnsupported => {
                "Spatial bbox invalid"
            }
            SpatialError::FilterUnsupported { .. } => "Spatial filter unsupported",
            SpatialError::CrsUnsupported => "Spatial CRS unsupported",
        }
    }

    fn detail(&self) -> String {
        match self {
            SpatialError::GeometryInvalid => "geometry field is malformed".to_string(),
            SpatialError::GeometryTooLarge => {
                "geometry exceeds the configured vertex limit".to_string()
            }
            SpatialError::BboxInvalid => {
                "bbox parameter is malformed or uses an unsupported shape".to_string()
            }
            SpatialError::BboxAntimeridianUnsupported => {
                "bbox crosses the antimeridian; antimeridian bboxes are not supported in Phase 1"
                    .to_string()
            }
            SpatialError::FilterUnsupported { parameter } => {
                let safe = sanitise_operator_string(parameter, MAX_SCOPE_NAME_LEN);
                truncate(
                    format!("parameter cannot be evaluated: {safe}"),
                    MAX_DETAIL_LEN,
                )
            }
            SpatialError::CrsUnsupported => "requested CRS is not supported".to_string(),
        }
    }
}

impl QueryError {
    fn code(&self) -> &'static str {
        match self {
            QueryError::CursorInvalid => "query.cursor_invalid",
        }
    }

    fn http_status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn title(&self) -> &'static str {
        match self {
            QueryError::CursorInvalid => "Query cursor invalid",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            QueryError::CursorInvalid => {
                "cursor is malformed, expired, or bound to a different query context"
            }
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let problem = self.to_problem();
        let code = self.code().to_string();
        let mut response = problem.into_response();
        // Attach the stable taxonomy code to the response so the audit
        // middleware can record `error_code` on every 4xx/5xx, including
        // the auth-failure short-circuit path that routes through this
        // impl.
        response
            .extensions_mut()
            .insert(crate::audit::ErrorCodeExt(code));
        response
    }
}

/// Strip control characters from an operator-supplied string and cap
/// its length. Used for scope names and any future operator-config
/// value that surfaces in a response body.
fn sanitise_operator_string(input: &str, max_len: usize) -> String {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_control())
        .take(max_len)
        .collect();
    if cleaned.is_empty() {
        "<unset>".to_string()
    } else {
        cleaned
    }
}

/// Truncate a string to `max_len` characters (not bytes) so that no
/// detail string exceeds the configured cap.
fn truncate(s: String, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        return s;
    }
    s.chars().take(max_len).collect()
}
