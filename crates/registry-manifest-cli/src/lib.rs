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

use clap::{Arg, ArgAction, Command};
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

const ARTIFACT_FORMATS: [&str; 12] = [
    "catalog",
    "evidence-offerings",
    "evidence-offering",
    "policies",
    "policy",
    "dcat",
    "bregdcat-ap",
    "cpsv-ap",
    "shacl",
    "json-schema",
    "form-json-schema",
    "ogc-records",
];

/// Registry Manifest's canonical public command tree.
///
/// The private executable sets its displayed binary name to `registry-manifest`.
/// The unified launcher and generated catalog retain the public product name
/// `manifest`, so help and metadata do not expose a private entrypoint.
pub fn command() -> Command {
    Command::new("manifest")
        .about("Validate, render, and publish portable registry metadata")
        .version(registry_platform_buildinfo::DISPLAY_VERSION)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(check_command(
            "validate",
            "Validate one Registry Manifest metadata document",
            Arg::new("metadata")
                .value_name("FILE")
                .help("Registry Manifest metadata document to validate")
                .required(true),
        ))
        .subcommand(check_command(
            "validate-profiles",
            "Validate profile descriptors and their declared fixtures",
            Arg::new("profiles")
                .value_name("DIRECTORY")
                .help("Directory containing Registry Manifest profiles")
                .default_value("profiles"),
        ))
        .subcommand(
            Command::new("render")
                .about("Render one artifact from a Registry Manifest document")
                .long_about(
                    "Render one artifact from a Registry Manifest document. The exact artifact \
                     JSON bytes are written to standard output; report --format does not apply.",
                )
                .arg(
                    Arg::new("metadata")
                        .value_name("FILE")
                        .help("Registry Manifest metadata document to render")
                        .required(true),
                )
                .arg(
                    Arg::new("artifact-format")
                        .long("artifact-format")
                        .value_name("ARTIFACT")
                        .help("Artifact to render to standard output")
                        .value_parser(ARTIFACT_FORMATS)
                        .required(true),
                )
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .value_name("ID")
                        .help("Declared DCAT application profile to render"),
                )
                .arg(
                    Arg::new("dataset")
                        .long("dataset")
                        .value_name("ID")
                        .help("Dataset whose policy or entity schema to render"),
                )
                .arg(
                    Arg::new("entity")
                        .long("entity")
                        .value_name("NAME")
                        .help("Entity whose JSON Schema to render"),
                )
                .arg(
                    Arg::new("form")
                        .long("form")
                        .value_name("ID")
                        .help("Form whose JSON Schema to render"),
                )
                .arg(
                    Arg::new("offering")
                        .long("offering")
                        .value_name("ID")
                        .help("Evidence offering document to render"),
                ),
        )
        .subcommand(
            Command::new("publish")
                .about("Publish a static Registry Manifest metadata bundle")
                .long_about(
                    "Publish a static Registry Manifest metadata bundle beneath --output. The \
                     command emits a separate human or JSON report and never writes artifact \
                     bytes to standard output.",
                )
                .arg(
                    Arg::new("metadata")
                        .value_name("FILE")
                        .help("Registry Manifest metadata document to publish")
                        .required(true),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .value_name("DIRECTORY")
                        .help("Directory that receives the metadata bundle")
                        .default_value("public/metadata"),
                )
                .arg(
                    Arg::new("site-root")
                        .long("site-root")
                        .value_name("DIRECTORY")
                        .help("Separate site root that receives .well-known discovery files"),
                )
                .arg(report_format()),
        )
}

fn check_command(name: &'static str, about: &'static str, path: Arg) -> Command {
    Command::new(name)
        .about(about)
        .arg(path)
        .arg(report_format())
        .arg(
            Arg::new("deny-warnings")
                .long("deny-warnings")
                .help("Treat warnings as a domain refusal")
                .action(ArgAction::SetTrue),
        )
}

fn report_format() -> Arg {
    Arg::new("format")
        .long("format")
        .value_name("FORMAT")
        .help("Report format")
        .value_parser(["human", "json"])
        .default_value("human")
}

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
