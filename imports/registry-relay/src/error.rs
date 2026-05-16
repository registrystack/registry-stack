// SPDX-License-Identifier: Apache-2.0
//! Stable error taxonomy and RFC 9457 Problem Details rendering.
//! (RFC 9457 obsoletes RFC 7807; the wire shape is identical.)
//!
//! Every code is namespaced (`auth.*`, `filter.*`, ...) and renders as
//! an `application/problem+json` response carrying the stable string
//! in the `code` extension member alongside the standard `type`,
//! `title`, `status`, and `detail` fields. The `type` URI is built
//! from a base URL plus the code with `.` rewritten to `/`.
//!
//! ## Startup-only codes
//!
//! `config.*` and `ingest.*` codes are surfaced via stderr at startup
//! or via `/ready`'s body, never as a direct response to a client
//! request. They still implement [`IntoResponse`] for defence in
//! depth: rendering one returns `500 Internal Server Error` with the
//! correct stable code. See the per-variant [`Error::http_status`]
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

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use http_api_problem::HttpApiProblem;
use serde_json::json;
use thiserror::Error;

/// Base URL for RFC 9457 `type` URIs. Becomes configurable in V1.x;
/// pinned at compile time for V1.
const PROBLEM_TYPE_BASE: &str = "https://data.example.gov/problems/";

/// Content-Type for RFC 9457 Problem Details responses.
const PROBLEM_JSON: &str = "application/problem+json";

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
    Internal(#[from] InternalError),
    /// Provenance runtime errors.
    #[error("{0}")]
    Provenance(#[from] ProvenanceError),
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
    #[error("aggregate measure unsupported")]
    MeasureUnsupported,
    #[error("disclosure violation")]
    DisclosureViolation,
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
    /// Signer kind is not one of `software` or `kms`.
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
            Error::Internal(e) => e.code(),
            Error::Provenance(e) => e.code(),
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
            Error::Internal(e) => e.http_status(),
            Error::Provenance(e) => e.http_status(),
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
            Error::Internal(e) => e.title(),
            Error::Provenance(e) => e.title(),
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
            Error::Internal(e) => e.detail().to_string(),
            Error::Provenance(e) => e.detail().to_string(),
        }
    }

    /// Build the RFC 9457 `type` URI for this error's stable code.
    fn type_uri(&self) -> String {
        let path = self.code().replace('.', "/");
        format!("{PROBLEM_TYPE_BASE}{path}")
    }

    /// Render the error as an [`HttpApiProblem`] with all required
    /// RFC 9457 fields and the stable `code` extension.
    fn to_problem(&self) -> HttpApiProblem {
        HttpApiProblem::new(self.http_status())
            .type_url(self.type_uri())
            .title(self.title())
            .detail(self.detail())
            .value("code", &json!(self.code()))
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
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            AuthError::MissingCredential
            | AuthError::InvalidCredential
            | AuthError::MalformedCredential => StatusCode::UNAUTHORIZED,
            AuthError::ScopeDenied { .. } | AuthError::AdminRequired => StatusCode::FORBIDDEN,
            AuthError::PurposeRequired => StatusCode::BAD_REQUEST,
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
        }
    }

    fn detail(&self) -> String {
        match self {
            AuthError::MissingCredential => {
                "no credential provided in Authorization or X-Api-Key header".to_string()
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
            AggregateError::MeasureUnsupported => "aggregate.measure_unsupported",
            AggregateError::DisclosureViolation => "aggregate.disclosure_violation",
        }
    }

    fn http_status(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn title(&self) -> &'static str {
        match self {
            AggregateError::ExecutionFailed => "Aggregate execution failed",
            AggregateError::MeasureUnsupported => "Aggregate measure unsupported",
            AggregateError::DisclosureViolation => "Disclosure violation",
        }
    }

    fn detail(&self) -> &'static str {
        match self {
            AggregateError::ExecutionFailed => "query engine returned an execution error",
            AggregateError::MeasureUnsupported => {
                "configured measure references a function that is not implemented"
            }
            // Note: this is an internal invariant violation. The
            // string is deliberately generic; nothing about the
            // offending group reaches the client.
            AggregateError::DisclosureViolation => {
                "disclosure-control invariant was violated before response"
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
                "signer kind must be one of software or kms"
            }
            ConfigError::ProvenanceJwkEnvMissing => {
                "the signing JWK environment variable is unset or empty"
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

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let problem = self.to_problem();
        let status = self.http_status();
        let code = self.code().to_string();
        let body = problem.json_bytes();
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
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
