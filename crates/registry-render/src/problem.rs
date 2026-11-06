//! The Render problem model: one closed vocabulary for every failure, with
//! stable exit codes for the CLI and status codes for HTTP.

use std::fmt;

use registry_platform_yaml::{Diagnostic, Report};

/// Base URI for RFC 9457 problem types, shared by HTTP responses and CLI
/// `--format json` failure documents.
pub const PROBLEM_TYPE_BASE: &str = "https://render.registrystack.org/problems";

/// The closed set of Render failure kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProblemKind {
    /// A CLI or request argument is malformed.
    InvalidArgument,
    /// The bundle manifest is missing or structurally invalid.
    ManifestInvalid,
    /// A package does not match its shared checksum envelope.
    BundleTampered,
    /// A runtime package lacks the shared checksum envelope.
    BundleUnsealed,
    /// A requested document type or locale is not in the bundle.
    UnknownDocument,
    /// A label referenced by a document is missing or invalid.
    LabelsInvalid,
    /// A bundle font cannot be loaded.
    FontInvalid,
    /// Request data violates the document's JSON Schema (pointers attached).
    DataInvalid,
    /// A request asset is missing, oversized, or not an allowed media type.
    AssetInvalid,
    /// `issuedAt` is absent where it is required.
    IssuedAtMissing,
    /// The Typst compile failed (message with file/line where resolvable).
    CompileFailed,
    /// Typst completed but reported warnings and `--strict` refused them.
    StrictWarnings,
    /// The render exceeded its output-size cap.
    OutputTooLarge,
    /// The worker was killed at the render timeout.
    RenderTimeout,
    /// The render worker panicked (recycled).
    RenderPanicked,
    /// The bearer credential is missing or invalid (HTTP 401).
    Unauthorized,
    /// The verified credential lacks Render operation scope (HTTP 403).
    Forbidden,
    /// The credential verifier cannot reach a verdict (HTTP 503).
    AuthenticationUnavailable,
    /// The HTTP route is not exposed by the adapter (HTTP 404).
    NotFound,
    /// The request body exceeds the configured ceiling (HTTP 413).
    BodyTooLarge,
    /// The caller exceeded a limit (HTTP 429/413 semantics).
    RateLimited,
    /// The audit destination refused or failed (fail closed before responding).
    AuditFailed,
    /// The runtime configuration is invalid.
    RuntimeInvalid,
    /// An internal invariant broke; never carries data.
    Internal,
    /// The seal's signer cannot sign now: its key provider is not ready
    /// (HTTP 503). Plain rendering is unaffected.
    SigningUnavailable,
    /// The seal's certificate cannot be used: unreadable, malformed, without
    /// a signing key usage, not matching its key, or outside its validity.
    SealCertificateInvalid,
    /// The timestamp authority did not return a usable token for a B-T seal
    /// (HTTP 502). Render never falls back to an untimestamped seal.
    TimestampFailed,
    /// The document type declares no seal, so it cannot be sealed.
    DocumentNotSealable,
    /// The verified client is not in the seal's `allowedClients` (HTTP 403).
    SealClientNotAllowed,
}

impl ProblemKind {
    /// Stable process exit code for CLI use (`--format json` scripts rely on it).
    /// One code per kind: scripts must be able to branch exactly.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidArgument => 2,
            Self::ManifestInvalid => 3,
            Self::BundleTampered => 4,
            Self::BundleUnsealed => 5,
            Self::UnknownDocument => 6,
            Self::LabelsInvalid => 7,
            Self::FontInvalid => 8,
            Self::DataInvalid => 9,
            Self::AssetInvalid => 10,
            Self::IssuedAtMissing => 11,
            Self::CompileFailed => 12,
            Self::StrictWarnings => 13,
            Self::OutputTooLarge => 14,
            Self::RenderTimeout => 15,
            Self::RenderPanicked => 16,
            Self::Unauthorized => 17,
            Self::Forbidden => 23,
            Self::AuthenticationUnavailable => 24,
            Self::NotFound => 25,
            Self::BodyTooLarge => 22,
            Self::RateLimited => 18,
            Self::AuditFailed => 19,
            Self::RuntimeInvalid => 20,
            Self::Internal => 21,
            Self::SigningUnavailable => 26,
            Self::SealCertificateInvalid => 27,
            Self::TimestampFailed => 28,
            Self::DocumentNotSealable => 29,
            Self::SealClientNotAllowed => 30,
        }
    }

    /// Shared HTTP problem code; CLI exit codes and slugs remain product-owned.
    pub fn http_code(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "render.invalid-argument",
            Self::ManifestInvalid => "render.manifest-invalid",
            Self::BundleTampered => "render.bundle-tampered",
            Self::BundleUnsealed => "render.bundle-unsealed",
            Self::UnknownDocument => "render.unknown-document",
            Self::LabelsInvalid => "render.labels-invalid",
            Self::FontInvalid => "render.font-invalid",
            Self::DataInvalid => "render.data-invalid",
            Self::AssetInvalid => "render.asset-invalid",
            Self::IssuedAtMissing => "render.issued-at-missing",
            Self::CompileFailed => "render.compile-failed",
            Self::StrictWarnings => "render.strict-warnings",
            Self::OutputTooLarge => "render.output-too-large",
            Self::RenderTimeout => "render.render-timeout",
            Self::RenderPanicked => "render.render-panicked",
            Self::Unauthorized => "render.unauthorized",
            Self::Forbidden => "render.forbidden",
            Self::AuthenticationUnavailable => "render.authentication-unavailable",
            Self::NotFound => "render.not-found",
            Self::BodyTooLarge => "render.body-too-large",
            Self::RateLimited => "render.rate-limited",
            Self::AuditFailed => "render.audit-failed",
            Self::RuntimeInvalid => "render.runtime-invalid",
            Self::Internal => "render.internal",
            Self::SigningUnavailable => "render.signing-unavailable",
            Self::SealCertificateInvalid => "render.seal-certificate-invalid",
            Self::TimestampFailed => "render.timestamp-failed",
            Self::DocumentNotSealable => "render.document-not-sealable",
            Self::SealClientNotAllowed => "render.seal-client-not-allowed",
        }
    }

    /// HTTP status for serve mode.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidArgument
            | Self::ManifestInvalid
            | Self::BundleTampered
            | Self::BundleUnsealed
            | Self::UnknownDocument
            | Self::LabelsInvalid
            | Self::FontInvalid
            | Self::DataInvalid
            | Self::AssetInvalid
            | Self::IssuedAtMissing
            | Self::DocumentNotSealable => 400,
            Self::CompileFailed | Self::StrictWarnings | Self::OutputTooLarge => 422,
            Self::RenderTimeout => 504,
            Self::RenderPanicked | Self::Internal => 500,
            Self::Unauthorized => 401,
            Self::Forbidden | Self::SealClientNotAllowed => 403,
            Self::AuthenticationUnavailable => 503,
            Self::NotFound => 404,
            Self::BodyTooLarge => 413,
            Self::RateLimited => 429,
            Self::AuditFailed
            | Self::RuntimeInvalid
            | Self::SigningUnavailable
            | Self::SealCertificateInvalid => 503,
            Self::TimestampFailed => 502,
        }
    }

    /// Machine-readable problem type slug (becomes the RFC 9457 type URI's
    /// final segment).
    pub fn slug(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid-argument",
            Self::ManifestInvalid => "manifest-invalid",
            Self::BundleTampered => "bundle-tampered",
            Self::BundleUnsealed => "bundle-unsealed",
            Self::UnknownDocument => "unknown-document",
            Self::LabelsInvalid => "labels-invalid",
            Self::FontInvalid => "font-invalid",
            Self::DataInvalid => "data-invalid",
            Self::AssetInvalid => "asset-invalid",
            Self::IssuedAtMissing => "issued-at-missing",
            Self::CompileFailed => "compile-failed",
            Self::StrictWarnings => "strict-warnings",
            Self::OutputTooLarge => "output-too-large",
            Self::RenderTimeout => "render-timeout",
            Self::RenderPanicked => "render-panicked",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::AuthenticationUnavailable => "authentication-unavailable",
            Self::NotFound => "not-found",
            Self::BodyTooLarge => "body-too-large",
            Self::RateLimited => "rate-limited",
            Self::AuditFailed => "audit-failed",
            Self::RuntimeInvalid => "runtime-invalid",
            Self::Internal => "internal",
            Self::SigningUnavailable => "signing-unavailable",
            Self::SealCertificateInvalid => "seal-certificate-invalid",
            Self::TimestampFailed => "timestamp-failed",
            Self::DocumentNotSealable => "document-not-sealable",
            Self::SealClientNotAllowed => "seal-client-not-allowed",
        }
    }
}

/// One Render failure: kind, human detail, and optional JSON pointers into
/// the request data or file paths inside the bundle. Problems never carry
/// request data values.
#[derive(Debug, Clone)]
pub struct RenderProblem {
    pub kind: ProblemKind,
    pub detail: String,
    /// JSON pointers (RFC 6901) into the request data, for schema failures.
    pub pointers: Vec<String>,
    /// Locations inside the bundle or template, for compile failures.
    pub locations: Vec<String>,
    /// The shared reader's diagnostics, unchanged, when a configuration file
    /// was refused (CFG-DIAG-1). The detail is the one sentence Render puts
    /// before them.
    pub diagnostics: Vec<Diagnostic>,
    /// Fixed, value-free text an HTTP caller reads in place of the kind's
    /// default guidance, when one kind covers several failing pieces (the
    /// timestamp authority unreachable or refusing, say). The `detail` above
    /// stays the operator's text and never reaches the caller.
    pub public_detail: Option<&'static str>,
}

impl RenderProblem {
    pub fn new(kind: ProblemKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            pointers: Vec::new(),
            locations: Vec::new(),
            diagnostics: Vec::new(),
            public_detail: None,
        }
    }

    pub fn with_public_detail(mut self, detail: &'static str) -> Self {
        self.public_detail = Some(detail);
        self
    }

    pub fn with_pointers(mut self, pointers: Vec<String>) -> Self {
        self.pointers = pointers;
        self
    }

    pub fn with_locations(mut self, locations: Vec<String>) -> Self {
        self.locations = locations;
        self
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    pub fn exit_code(&self) -> i32 {
        self.kind.exit_code()
    }

    /// The problem as an operator reads it on standard error: one line of
    /// Render's own, then each reader diagnostic in the shared human shape
    /// with its summary line (CFG-DIAG-2).
    pub fn render_human(&self) -> String {
        let mut out = format!("registry-render: {self}\n");
        if !self.diagnostics.is_empty() {
            out.push_str(&Report::new(self.diagnostics.clone()).render_human());
        }
        out
    }
}

impl fmt::Display for RenderProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.slug(), self.detail)?;
        if !self.pointers.is_empty() {
            write!(f, " (at {})", self.pointers.join(", "))?;
        }
        if !self.locations.is_empty() {
            write!(f, " (in {})", self.locations.join(", "))?;
        }
        Ok(())
    }
}

impl std::error::Error for RenderProblem {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_stable_and_unique() {
        let kinds = [
            ProblemKind::InvalidArgument,
            ProblemKind::ManifestInvalid,
            ProblemKind::BundleTampered,
            ProblemKind::BundleUnsealed,
            ProblemKind::UnknownDocument,
            ProblemKind::LabelsInvalid,
            ProblemKind::FontInvalid,
            ProblemKind::DataInvalid,
            ProblemKind::AssetInvalid,
            ProblemKind::IssuedAtMissing,
            ProblemKind::CompileFailed,
            ProblemKind::StrictWarnings,
            ProblemKind::OutputTooLarge,
            ProblemKind::RenderTimeout,
            ProblemKind::RenderPanicked,
            ProblemKind::Unauthorized,
            ProblemKind::Forbidden,
            ProblemKind::AuthenticationUnavailable,
            ProblemKind::NotFound,
            ProblemKind::BodyTooLarge,
            ProblemKind::RateLimited,
            ProblemKind::AuditFailed,
            ProblemKind::RuntimeInvalid,
            ProblemKind::Internal,
            ProblemKind::SigningUnavailable,
            ProblemKind::SealCertificateInvalid,
            ProblemKind::TimestampFailed,
            ProblemKind::DocumentNotSealable,
            ProblemKind::SealClientNotAllowed,
        ];
        let slugs: Vec<&str> = kinds.iter().map(|k| k.slug()).collect();
        let mut sorted = slugs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), slugs.len(), "slugs must be unique");
        let mut codes: Vec<i32> = kinds.iter().map(|k| k.exit_code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), kinds.len(), "exit codes must be unique");
    }

    #[test]
    fn seal_kinds_name_their_status_type_and_exit_code() {
        for (kind, status, slug, exit) in [
            (
                ProblemKind::SigningUnavailable,
                503,
                "signing-unavailable",
                26,
            ),
            (
                ProblemKind::SealCertificateInvalid,
                503,
                "seal-certificate-invalid",
                27,
            ),
            (ProblemKind::TimestampFailed, 502, "timestamp-failed", 28),
            (
                ProblemKind::DocumentNotSealable,
                400,
                "document-not-sealable",
                29,
            ),
            (
                ProblemKind::SealClientNotAllowed,
                403,
                "seal-client-not-allowed",
                30,
            ),
        ] {
            assert_eq!(kind.http_status(), status, "{kind:?}");
            assert_eq!(kind.slug(), slug);
            assert_eq!(kind.http_code(), format!("render.{slug}"));
            assert_eq!(kind.exit_code(), exit);
            assert_eq!(
                ProblemKind::from_slug(slug),
                ProblemKind::Internal,
                "the worker holds no signer, so a worker naming a signing failure is an internal fault"
            );
        }
    }

    #[test]
    fn a_public_detail_names_the_failing_piece_and_nothing_else() {
        let problem = RenderProblem::new(ProblemKind::TimestampFailed, "operator text")
            .with_public_detail("The timestamp authority could not be reached; retry later.");
        assert_eq!(
            problem.public_detail,
            Some("The timestamp authority could not be reached; retry later.")
        );
        assert_eq!(
            RenderProblem::new(ProblemKind::Internal, "x").public_detail,
            None
        );
    }
}
