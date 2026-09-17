//! The Render problem model: one closed vocabulary for every failure, with
//! stable exit codes for the CLI and status codes for HTTP.

use std::fmt;

/// The closed set of Render failure kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProblemKind {
    /// A CLI or request argument is malformed.
    InvalidArgument,
    /// The bundle manifest is missing or structurally invalid.
    ManifestInvalid,
    /// A sealed bundle's file hashes do not match the manifest.
    BundleTampered,
    /// An operation requires a sealed bundle and the bundle is unsealed.
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
    /// The caller's API key is missing or wrong (HTTP 401).
    Unauthorized,
    /// The caller exceeded a limit (HTTP 429/413 semantics).
    RateLimited,
    /// The audit ledger refused or failed (fail closed before responding).
    AuditFailed,
    /// The runtime configuration is invalid.
    RuntimeInvalid,
    /// An internal invariant broke; never carries data.
    Internal,
}

impl ProblemKind {
    /// Stable process exit code for CLI use (`--json` scripts rely on it).
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
            Self::RateLimited => 18,
            Self::AuditFailed => 19,
            Self::RuntimeInvalid => 20,
            Self::Internal => 21,
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
            | Self::IssuedAtMissing => 400,
            Self::CompileFailed | Self::StrictWarnings | Self::OutputTooLarge => 422,
            Self::RenderTimeout => 504,
            Self::RenderPanicked | Self::Internal => 500,
            Self::Unauthorized => 401,
            Self::RateLimited => 429,
            Self::AuditFailed | Self::RuntimeInvalid => 503,
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
            Self::RateLimited => "rate-limited",
            Self::AuditFailed => "audit-failed",
            Self::RuntimeInvalid => "runtime-invalid",
            Self::Internal => "internal",
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
}

impl RenderProblem {
    pub fn new(kind: ProblemKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            pointers: Vec::new(),
            locations: Vec::new(),
        }
    }

    pub fn with_pointers(mut self, pointers: Vec<String>) -> Self {
        self.pointers = pointers;
        self
    }

    pub fn with_locations(mut self, locations: Vec<String>) -> Self {
        self.locations = locations;
        self
    }

    pub fn exit_code(&self) -> i32 {
        self.kind.exit_code()
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
            ProblemKind::RateLimited,
            ProblemKind::AuditFailed,
            ProblemKind::RuntimeInvalid,
            ProblemKind::Internal,
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
}
