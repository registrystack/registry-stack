// SPDX-License-Identifier: Apache-2.0
//! Registry Manifest's reading of its two authored formats, and the offline
//! checks `registry-manifest validate` and `registry-manifest
//! validate-profiles` run (CFG-CHECK-1).
//!
//! A metadata manifest and a profile descriptor are exchange models that
//! name their version in `schema_version`, so neither carries `apiVersion`
//! and `kind`. Both are read by the shared configuration reader: every
//! finding is a diagnostic with a stable code, a JSON pointer, a line and
//! column where the file has one, a message that never repeats a value from
//! the file, and the action that fixes it.

use std::fs;
use std::io::{self, Read as _};
use std::path::Path;

use registry_platform_yaml::{
    Diagnostic, EnvelopeRule, FormatSpec, Report, Severity, Source, MAXIMUM_DOCUMENT_BYTES,
};

mod metadata;
mod profile;
#[cfg(feature = "schema")]
pub mod schema;

pub use metadata::{
    check_metadata_file, manifest_digest, metadata_error_diagnostics, read_metadata,
    validation_pointer, MetadataCheck, ReadManifest,
};
pub use profile::{
    check_profiles, CardinalityExpectation, CheckSeverity, CodelistExpectation, ConceptExpectation,
    ConformanceCheck, FixtureExpectation, IdentifierExpectation, InputArtifact, ProfileDescriptor,
    ProfileFixture, ProfileIdentity, ProfileSchemaVersion, ProfilesCheck, UnsupportedMapping,
};

/// The `apiVersion` of the report `validate --format json` and
/// `validate-profiles --format json` write.
pub const CTL_REPORT_API_VERSION: &str =
    "id.registrystack.org/formats/manifest/ctl-report/v1alpha1";
/// The `kind` of that report.
pub const CTL_REPORT_KIND: &str = "ManifestCtlReport";
/// The artifact name a metadata manifest's diagnostics carry.
pub const METADATA_KIND: &str = "ManifestMetadata";
/// The artifact name a profile descriptor's diagnostics carry.
pub const PROFILE_KIND: &str = "ManifestProfile";
/// The `schema_version` a metadata manifest declares.
pub const METADATA_SCHEMA_VERSION: &str = "registry-manifest/v1";
/// The `schema_version` a profile descriptor declares.
pub const PROFILE_SCHEMA_VERSION: &str = "registry-manifest-profile/v1";
/// The file name of a profile descriptor inside its profile's directory.
pub const PROFILE_FILE_NAME: &str = "profile.yaml";

/// A metadata manifest, as the shared reader reads it.
pub const METADATA_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: METADATA_KIND,
    envelope: EnvelopeRule::Exempt {
        reason: "a metadata manifest is an exchange model that names its version in \
                 schema_version",
    },
    removed_keys: &[],
};

/// A profile descriptor, as the shared reader reads it.
pub const PROFILE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: PROFILE_KIND,
    envelope: EnvelopeRule::Exempt {
        reason: "a profile descriptor is an exchange model that names its version in \
                 schema_version",
    },
    removed_keys: &[],
};

/// What one check found, before it becomes a [`Report`].
#[derive(Default)]
struct Findings {
    diagnostics: Vec<Diagnostic>,
    files: usize,
    unavailable: bool,
}

impl Findings {
    fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    fn extend(&mut self, diagnostics: impl IntoIterator<Item = Diagnostic>) {
        self.diagnostics.extend(diagnostics);
    }

    fn into_report(self) -> (Report, bool) {
        let mut report = Report::new(self.diagnostics);
        report.set_files_checked(self.files);
        (report, self.unavailable)
    }

    /// A file or directory that could not be read at all: the check cannot
    /// finish, and exits 3.
    fn unreadable(&mut self, code: &str, file: &Path, message: &str, action: &str) {
        self.unavailable = true;
        self.push(about(Severity::Error, code, file, message, action));
    }
}

/// A diagnostic about a file or directory as a whole, with no line.
fn about(severity: Severity, code: &str, file: &Path, message: &str, action: &str) -> Diagnostic {
    let mut diagnostic = match severity {
        Severity::Error => Diagnostic::error(code, "", message, action),
        Severity::Warning => Diagnostic::warning(code, "", message, action),
    };
    diagnostic.source = Some(Source {
        file: file.display().to_string(),
        line: None,
        column: None,
    });
    diagnostic
}

enum Contents {
    Bytes(Vec<u8>),
    Missing,
    Unreadable,
}

/// The file's bytes, up to one byte past the reader's size cap so the
/// reader refuses an oversized file itself. A link is followed; a path
/// that is not a regular file once followed is unreadable.
fn contents(path: &Path) -> Contents {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Contents::Missing,
        Err(_) => return Contents::Unreadable,
    };
    if !metadata.is_file() {
        return Contents::Unreadable;
    }
    let Ok(file) = fs::File::open(path) else {
        return Contents::Unreadable;
    };
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAXIMUM_DOCUMENT_BYTES).map_or(u64::MAX, |bound| bound + 1);
    match file.take(limit).read_to_end(&mut bytes) {
        Ok(_) => Contents::Bytes(bytes),
        Err(_) => Contents::Unreadable,
    }
}
