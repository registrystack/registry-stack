// SPDX-License-Identifier: Apache-2.0

//! The Discovery authoring project, read through the shared reader.
//!
//! A project is one directory: `origins.yaml`, a `mappings` directory of
//! evidence mapping files, and usually the runtime file `runtime.yaml`. The
//! authored files are reviewed and packaged as written, so a `${...}`
//! expression in one is refused (CFG-SEC-2). Every file is read before
//! anything is judged, a value check runs only on a file that decoded
//! cleanly, and every finding names its position and its fix (CFG-DIAG-5,
//! CFG-DIAG-6).

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Read as _};
use std::path::{Component, Path, PathBuf};

use registry_discovery::{check_runtime, RUNTIME_KIND};
use registry_platform_yaml::{
    Diagnostic, Document, EnvelopeRule, Expect, FormatSpec, NodeValue, Position, Reader, Related,
    Report, Severity, Source, UniqueList, Url, MAXIMUM_DOCUMENT_BYTES,
};
use serde::{Deserialize, Serialize};

pub const ORIGINS_SCHEMA: &str = "registry-discovery/origins/v1alpha1";
pub const MAPPING_SCHEMA: &str = "registry-discovery/evidence-mapping/v1alpha1";
/// The name diagnostics give an origins file.
pub const ORIGINS_KIND: &str = "DiscoveryOrigins";
/// The name diagnostics give an evidence mapping file.
pub const MAPPING_KIND: &str = "DiscoveryEvidenceMapping";
pub const ORIGINS_FILE: &str = "origins.yaml";
pub const MAPPINGS_DIRECTORY: &str = "mappings";
pub const MAX_ORIGINS: usize = 128;
pub const MAX_MAPPINGS: usize = 2_048;
pub const MAX_ALTERNATIVES: usize = 32;
pub const MAX_EVIDENCE_TYPES_PER_ALTERNATIVE: usize = 32;
const MAX_ORIGIN_ID_BYTES: usize = 128;
const MAX_IDENTIFIER_CHARACTERS: usize = 4_096;
#[cfg(feature = "schema")]
const ORIGIN_ID_PATTERN: &str = "^[A-Za-z0-9._-]+$";
#[cfg(feature = "schema")]
const IDENTIFIER_PATTERN: &str = "^[^\\s\\u0000-\\u001F\\u007F-\\u009F]+$";
#[cfg(feature = "schema")]
const CATALOG_URL_PATTERN: &str = "^https://[^\\s\\u0000-\\u001F\\u007F-\\u009F/?#@]+(?!.*//)(?:/[^\\s\\u0000-\\u001F\\u007F-\\u009F?#]*)?$";

const ORIGINS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ORIGINS_KIND,
    envelope: EnvelopeRule::Exempt {
        reason: "the origins file keeps its schemaVersion header until the recorded move to \
                 apiVersion and kind",
    },
    removed_keys: &[],
};

const MAPPING_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: MAPPING_KIND,
    envelope: EnvelopeRule::Exempt {
        reason: "the evidence mapping file keeps its schemaVersion header until the recorded \
                 move to apiVersion and kind",
    },
    removed_keys: &[],
};

/// The header an origins file carries.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum OriginsSchemaVersion {
    #[serde(rename = "registry-discovery/origins/v1alpha1")]
    V1Alpha1,
}

/// The header an evidence mapping file carries.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum MappingSchemaVersion {
    #[serde(rename = "registry-discovery/evidence-mapping/v1alpha1")]
    V1Alpha1,
}

/// The publication profile an approved origin implements.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum OriginProfile {
    #[serde(rename = "registry-discovery-v1alpha1")]
    RegistryDiscoveryV1Alpha1,
}

/// The origins the operator approves for one index.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OriginsFile {
    pub schema_version: OriginsSchemaVersion,
    /// One to 128 approved origins.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = MAX_ORIGINS)))]
    pub origins: Vec<ApprovedOrigin>,
}

/// One approved origin: a provider whose public description the index
/// collects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ApprovedOrigin {
    /// The origin's name in this project: 1 to 128 characters from `A-Z`,
    /// `a-z`, `0-9`, `.`, `_`, and `-`.
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = MAX_ORIGIN_ID_BYTES), regex(pattern = ORIGIN_ID_PATTERN))
    )]
    pub origin_id: String,
    /// Exact production HTTPS URL without credentials, query, or fragment.
    /// Loopback HTTP is a development exception `discoveryctl` accepts only
    /// with `--allow-loopback`, not part of this production authoring schema.
    #[cfg_attr(feature = "schema", schemars(extend("pattern" = CATALOG_URL_PATTERN)))]
    pub catalog_url: Url,
    pub profile: OriginProfile,
    /// Whether `discoveryctl package` collects this origin.
    pub enabled: bool,
}

/// One requirement and the evidence type alternatives that satisfy it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AuthoredEvidenceMapping {
    pub schema_version: MappingSchemaVersion,
    /// An absolute URI of at most 4096 characters, unique in the project.
    #[cfg_attr(
        feature = "schema",
        schemars(url, length(min = 1, max = MAX_IDENTIFIER_CHARACTERS), regex(pattern = IDENTIFIER_PATTERN))
    )]
    pub mapping_id: String,
    /// An absolute URI of at most 4096 characters.
    #[cfg_attr(
        feature = "schema",
        schemars(url, length(min = 1, max = MAX_IDENTIFIER_CHARACTERS), regex(pattern = IDENTIFIER_PATTERN))
    )]
    pub mapping_authority_id: String,
    /// An absolute URI of at most 4096 characters.
    #[cfg_attr(
        feature = "schema",
        schemars(url, length(min = 1, max = MAX_IDENTIFIER_CHARACTERS), regex(pattern = IDENTIFIER_PATTERN))
    )]
    pub requirement_id: String,
    /// An absolute URI of at most 4096 characters. Leave the key out for a
    /// mapping that applies in every jurisdiction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(url, length(min = 1, max = MAX_IDENTIFIER_CHARACTERS), regex(pattern = IDENTIFIER_PATTERN))
    )]
    pub jurisdiction: Option<String>,
    /// One to 32 alternatives; any one of them satisfies the requirement.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = MAX_ALTERNATIVES)))]
    pub alternatives: Vec<AuthoredEvidenceTypeAlternative>,
}

/// One evidence type list and the evidence types taken from it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AuthoredEvidenceTypeAlternative {
    /// An absolute URI of at most 4096 characters, unique in the mapping.
    #[cfg_attr(
        feature = "schema",
        schemars(url, length(min = 1, max = MAX_IDENTIFIER_CHARACTERS), regex(pattern = IDENTIFIER_PATTERN))
    )]
    pub evidence_type_list_id: String,
    /// One to 32 distinct absolute URIs, each of at most 4096 characters.
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 1, max = MAX_EVIDENCE_TYPES_PER_ALTERNATIVE),
            inner(url, length(min = 1, max = MAX_IDENTIFIER_CHARACTERS), regex(pattern = IDENTIFIER_PATTERN))
        )
    )]
    pub evidence_type_ids: UniqueList<String>,
}

/// A project that passed every check, with each mapping's alternatives and
/// evidence types in their canonical order.
#[derive(Clone, Debug)]
pub struct CheckedProject {
    pub origins: Vec<ApprovedOrigin>,
    pub mappings: Vec<AuthoredEvidenceMapping>,
}

/// How a project is checked.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProjectOptions {
    /// Accept an `http` loopback catalog URL, for development.
    pub allow_loopback: bool,
    /// Fill the runtime file's `${NAME}` expressions from the process
    /// environment and check every value. Without it, a member that holds an
    /// expression is checked by syntax and position only.
    pub environment: bool,
}

/// Everything one project check found.
#[derive(Debug)]
pub struct ProjectReport {
    pub report: Report,
    /// A file or directory could not be read at all, as opposed to read and
    /// refused.
    pub unavailable: bool,
    /// The origins and mappings, when they passed every check.
    pub project: Option<CheckedProject>,
}

/// The authored files of a project were refused or could not be read.
#[derive(Debug)]
pub struct ProjectError {
    pub report: Report,
    pub unavailable: bool,
}

impl fmt::Display for ProjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "the Discovery authoring project was refused:")?;
        formatter.write_str(self.report.render_human().trim_end())
    }
}

impl std::error::Error for ProjectError {}

/// Check every file of the project at `root` without network access
/// (CFG-CHECK-1, CFG-CHECK-2): `origins.yaml`, every file under `mappings`,
/// and each `.yaml` or `.yml` file beside them, which is checked as the
/// runtime file when it is one and refused when it is another kind.
#[must_use]
pub fn inspect_project(root: &Path, options: ProjectOptions) -> ProjectReport {
    let mut findings = Findings::default();
    let project = read_authored(root, options.allow_loopback, &mut findings);
    if !findings.unavailable {
        check_root_files(root, options.environment, &mut findings);
    }
    let unavailable = findings.unavailable;
    let report = findings.into_report();
    let project = project.filter(|_| !report.has_errors());
    ProjectReport {
        report,
        unavailable,
        project,
    }
}

/// Read and check the authored files of the project at `root`, the
/// origins and the mappings, without network access.
pub fn check_project(root: &Path, allow_loopback: bool) -> Result<CheckedProject, ProjectError> {
    let mut findings = Findings::default();
    let project = read_authored(root, allow_loopback, &mut findings);
    let unavailable = findings.unavailable;
    let report = findings.into_report();
    match project {
        Some(project) if !report.has_errors() => Ok(project),
        _ => Err(ProjectError {
            report,
            unavailable,
        }),
    }
}

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

    fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
    }

    fn into_report(self) -> Report {
        let mut report = Report::new(self.diagnostics);
        report.set_files_checked(self.files);
        report
    }

    /// A finding about a file or directory as a whole.
    fn about(&mut self, severity: Severity, code: &str, file: &Path, message: &str, action: &str) {
        let mut diagnostic = match severity {
            Severity::Error => Diagnostic::error(code, "", message, action),
            Severity::Warning => Diagnostic::warning(code, "", message, action),
        };
        diagnostic.source = Some(Source {
            file: file.display().to_string(),
            line: None,
            column: None,
        });
        self.push(diagnostic);
    }

    fn unreadable(&mut self, file: &Path) {
        self.unavailable = true;
        self.about(
            Severity::Error,
            "discovery.project.unreadable",
            file,
            "the file or directory could not be read",
            "Check that it exists and that this user may read it, then run the check again.",
        );
    }
}

fn read_authored(
    root: &Path,
    allow_loopback: bool,
    findings: &mut Findings,
) -> Option<CheckedProject> {
    match fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            findings.unavailable = true;
            findings.about(
                Severity::Error,
                "discovery.project.not-a-directory",
                root,
                "the project path is not a directory",
                "Pass the directory that holds origins.yaml and the mappings directory.",
            );
            return None;
        }
        Err(_) => {
            findings.unreadable(root);
            return None;
        }
    }

    let origins_path = root.join(ORIGINS_FILE);
    let origins = read_document::<OriginsFile>(&origins_path, &ORIGINS_FORMAT, findings).and_then(
        |(document, origins)| {
            let before = findings.diagnostics.len();
            check_origins(&document, &origins, allow_loopback, findings);
            (findings.diagnostics.len() == before).then_some(origins.origins)
        },
    );

    let mappings = read_mappings(&root.join(MAPPINGS_DIRECTORY), findings);
    match (origins, mappings) {
        (Some(origins), Some(mappings)) if !findings.has_errors() => {
            Some(CheckedProject { origins, mappings })
        }
        _ => None,
    }
}

enum Contents {
    Bytes(Vec<u8>),
    Missing,
    NotRegular,
    Unreadable,
}

/// The file's bytes, up to one byte past the reader's size cap so the
/// reader refuses an oversized file itself.
fn contents(path: &Path) -> Contents {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Contents::Missing,
        Err(_) => return Contents::Unreadable,
    };
    if !metadata.file_type().is_file() {
        return Contents::NotRegular;
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

/// Read one authored file of `format`, refusing every `${...}` expression.
fn read_document<T: serde::de::DeserializeOwned>(
    path: &Path,
    format: &FormatSpec<'_>,
    findings: &mut Findings,
) -> Option<(Document, T)> {
    let bytes = match contents(path) {
        Contents::Bytes(bytes) => bytes,
        Contents::Missing => {
            findings.about(
                Severity::Error,
                "discovery.project.missing-file",
                path,
                "the project has no origins.yaml",
                "Write origins.yaml in the project directory, listing the approved origins.",
            );
            return None;
        }
        Contents::NotRegular => {
            findings.about(
                Severity::Error,
                "discovery.project.not-a-regular-file",
                path,
                "the file is not a regular file",
                "Replace the link or directory with a regular file.",
            );
            return None;
        }
        Contents::Unreadable => {
            findings.unreadable(path);
            return None;
        }
    };
    findings.files += 1;
    let mut hook = registry_platform_config::AuthoredExpressions;
    match Reader::new(path.display().to_string())
        .with_hook(&mut hook)
        .decode::<T>(&bytes, &Expect::one(format))
    {
        Ok(decoded) => {
            findings.extend(decoded.document.warnings().into_diagnostics());
            Some((decoded.document, decoded.value))
        }
        Err(report) => {
            findings.extend(report.into_diagnostics());
            None
        }
    }
}

fn error_at(
    document: &Document,
    code: &str,
    pointer: &str,
    message: &str,
    action: &str,
) -> Diagnostic {
    document.diagnostic_at_value(Severity::Error, code, pointer, message, action)
}

fn related(document: &Document, pointer: &str, message: &str) -> Related {
    let position = document.span_of(pointer).map(|span| span.start);
    related_at(document.file(), position, pointer, message)
}

fn related_at(file: &str, position: Option<Position>, pointer: &str, message: &str) -> Related {
    Related {
        file: file.to_owned(),
        line: position.map(|position| position.line),
        column: position.map(|position| position.column),
        path: pointer.to_owned(),
        message: message.to_owned(),
    }
}

fn check_origins(
    document: &Document,
    file: &OriginsFile,
    allow_loopback: bool,
    findings: &mut Findings,
) {
    if file.origins.is_empty() || file.origins.len() > MAX_ORIGINS {
        findings.push(error_at(
            document,
            "discovery.origins.origin-count",
            "/origins",
            "a project approves 1 to 128 origins",
            "List at least one origin, and at most 128.",
        ));
    }
    let mut ids: BTreeMap<&str, String> = BTreeMap::new();
    let mut urls: BTreeMap<&str, String> = BTreeMap::new();
    for (index, origin) in file.origins.iter().enumerate() {
        let id_pointer = format!("/origins/{index}/originId");
        let url_pointer = format!("/origins/{index}/catalogUrl");
        if !valid_origin_id(&origin.origin_id) {
            findings.push(error_at(
                document,
                "discovery.origins.invalid-origin-id",
                &id_pointer,
                "an originId is 1 to 128 characters from A-Z, a-z, 0-9, `.`, `_`, and `-`",
                "Rename the origin using only letters, digits, `.`, `_`, and `-`.",
            ));
        } else if let Some(first) = ids.get(origin.origin_id.as_str()) {
            let mut diagnostic = error_at(
                document,
                "discovery.origins.duplicate-origin-id",
                &id_pointer,
                "an earlier origin already has this originId",
                "Give each origin its own originId.",
            );
            diagnostic.related.push(related(
                document,
                first,
                "the first origin with this originId",
            ));
            findings.push(diagnostic);
        } else {
            ids.insert(&origin.origin_id, id_pointer);
        }
        if !valid_catalog_url(origin.catalog_url.as_str(), allow_loopback) {
            findings.push(error_at(
                document,
                "discovery.origins.catalog-url-not-allowed",
                &url_pointer,
                "a catalogUrl is an https URL with no query, fragment, empty path segment, \
                 whitespace, or control character",
                "Write an https catalog URL with no query or fragment, or pass --allow-loopback \
                 for an http loopback origin during development.",
            ));
        } else if let Some(first) = urls.get(origin.catalog_url.as_str()) {
            let mut diagnostic = error_at(
                document,
                "discovery.origins.duplicate-catalog-url",
                &url_pointer,
                "an earlier origin already has this catalogUrl",
                "Approve each catalog once; remove the second origin.",
            );
            diagnostic.related.push(related(
                document,
                first,
                "the first origin with this catalogUrl",
            ));
            findings.push(diagnostic);
        } else {
            urls.insert(origin.catalog_url.as_str(), url_pointer);
        }
    }
}

/// Where a mapping's identity was first written, for duplicate notes.
struct FirstMapping {
    file: String,
    position: Option<Position>,
}

fn read_mappings(
    directory: &Path,
    findings: &mut Findings,
) -> Option<Vec<AuthoredEvidenceMapping>> {
    let entries = match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::read_dir(directory),
        Ok(_) => {
            findings.about(
                Severity::Error,
                "discovery.project.not-a-directory",
                directory,
                "mappings is not a directory",
                "Replace it with a directory of mapping files, empty when the project maps no \
                 requirement.",
            );
            return None;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            findings.about(
                Severity::Error,
                "discovery.project.missing-file",
                directory,
                "the project has no mappings directory",
                "Create the mappings directory, empty when the project maps no requirement.",
            );
            return None;
        }
        Err(_) => {
            findings.unreadable(directory);
            return None;
        }
    };
    let Ok(entries) = entries else {
        findings.unreadable(directory);
        return None;
    };
    let mut paths = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            findings.unreadable(directory);
            return None;
        };
        paths.push(entry.path());
    }
    paths.sort();
    if paths.len() > MAX_MAPPINGS {
        findings.about(
            Severity::Error,
            "discovery.project.mapping-count",
            directory,
            "a project holds at most 2048 mapping files",
            "Remove mapping files until at most 2048 remain.",
        );
    }

    let before = findings.diagnostics.len();
    let mut mappings = Vec::with_capacity(paths.len());
    let mut ids: BTreeMap<String, FirstMapping> = BTreeMap::new();
    let mut requirements: BTreeMap<(String, Option<String>), FirstMapping> = BTreeMap::new();
    for path in paths {
        if !is_yaml(&path)
            || !matches!(fs::symlink_metadata(&path), Ok(metadata) if metadata.file_type().is_file())
        {
            findings.about(
                Severity::Error,
                "discovery.project.unexpected-mapping-entry",
                &path,
                "the mappings directory holds an entry that is not a regular .yaml or .yml file",
                "Move it out of the mappings directory; it holds mapping files only.",
            );
            continue;
        }
        let Some((document, mapping)) =
            read_document::<AuthoredEvidenceMapping>(&path, &MAPPING_FORMAT, findings)
        else {
            continue;
        };
        if !check_mapping(&document, &mapping, findings) {
            continue;
        }
        let id_position = document.span_of("/mappingId").map(|span| span.start);
        if let Some(first) = ids.get(&mapping.mapping_id) {
            let mut diagnostic = error_at(
                &document,
                "discovery.project.duplicate-mapping-id",
                "/mappingId",
                "another mapping file already has this mappingId",
                "Give each mapping its own mappingId.",
            );
            diagnostic.related.push(related_at(
                &first.file,
                first.position,
                "/mappingId",
                "the first mapping with this mappingId",
            ));
            findings.push(diagnostic);
        } else {
            ids.insert(
                mapping.mapping_id.clone(),
                FirstMapping {
                    file: document.file().to_owned(),
                    position: id_position,
                },
            );
        }
        let requirement = (mapping.requirement_id.clone(), mapping.jurisdiction.clone());
        let requirement_position = document.span_of("/requirementId").map(|span| span.start);
        if let Some(first) = requirements.get(&requirement) {
            let mut diagnostic = error_at(
                &document,
                "discovery.project.duplicate-requirement",
                "/requirementId",
                "another mapping file already maps this requirementId in the same jurisdiction",
                "Merge the two mappings into one file, or correct the jurisdiction of one of them.",
            );
            diagnostic.related.push(related_at(
                &first.file,
                first.position,
                "/requirementId",
                "the first mapping of this requirement",
            ));
            findings.push(diagnostic);
        } else {
            requirements.insert(
                requirement,
                FirstMapping {
                    file: document.file().to_owned(),
                    position: requirement_position,
                },
            );
        }
        mappings.push(canonical_mapping(mapping));
    }
    if findings.diagnostics.len() != before {
        return None;
    }
    mappings.sort_by(|left, right| left.mapping_id.cmp(&right.mapping_id));
    Some(mappings)
}

/// The mapping with its evidence types sorted and its alternatives in order
/// of list identifier, then evidence types.
fn canonical_mapping(mut mapping: AuthoredEvidenceMapping) -> AuthoredEvidenceMapping {
    for alternative in &mut mapping.alternatives {
        let mut ids = std::mem::take(&mut alternative.evidence_type_ids).into_vec();
        ids.sort();
        alternative.evidence_type_ids =
            UniqueList::new(ids).expect("sorting a unique list keeps it unique");
    }
    mapping.alternatives.sort_by(|left, right| {
        left.evidence_type_list_id
            .cmp(&right.evidence_type_list_id)
            .then_with(|| left.evidence_type_ids[..].cmp(&right.evidence_type_ids[..]))
    });
    mapping
}

/// Check one decoded mapping's values. True when it passed.
fn check_mapping(
    document: &Document,
    mapping: &AuthoredEvidenceMapping,
    findings: &mut Findings,
) -> bool {
    let before = findings.diagnostics.len();
    let identifier = |pointer: &str, value: &str, findings: &mut Findings| {
        if !valid_identifier(value) {
            findings.push(error_at(
                document,
                "discovery.mapping.invalid-identifier",
                pointer,
                "this identifier is not an absolute URI of at most 4096 characters without \
                 whitespace or control characters",
                "Write an absolute URI, such as a `urn:` or `https:` identifier, with no spaces.",
            ));
        }
    };
    identifier("/mappingId", &mapping.mapping_id, findings);
    identifier(
        "/mappingAuthorityId",
        &mapping.mapping_authority_id,
        findings,
    );
    identifier("/requirementId", &mapping.requirement_id, findings);
    if let Some(jurisdiction) = &mapping.jurisdiction {
        identifier("/jurisdiction", jurisdiction, findings);
    }
    if mapping.alternatives.is_empty() || mapping.alternatives.len() > MAX_ALTERNATIVES {
        findings.push(error_at(
            document,
            "discovery.mapping.alternative-count",
            "/alternatives",
            "a mapping has 1 to 32 alternatives",
            "List at least one alternative, and at most 32.",
        ));
    }
    let mut lists: BTreeMap<&str, String> = BTreeMap::new();
    for (index, alternative) in mapping.alternatives.iter().enumerate() {
        let list_pointer = format!("/alternatives/{index}/evidenceTypeListId");
        let ids_pointer = format!("/alternatives/{index}/evidenceTypeIds");
        identifier(&list_pointer, &alternative.evidence_type_list_id, findings);
        if let Some(first) = lists.get(alternative.evidence_type_list_id.as_str()) {
            let mut diagnostic = error_at(
                document,
                "discovery.mapping.duplicate-evidence-type-list",
                &list_pointer,
                "an earlier alternative already takes evidence types from this list",
                "Merge the two alternatives into one.",
            );
            diagnostic.related.push(related(
                document,
                first,
                "the first alternative with this evidenceTypeListId",
            ));
            findings.push(diagnostic);
        } else {
            lists.insert(&alternative.evidence_type_list_id, list_pointer);
        }
        if alternative.evidence_type_ids.is_empty()
            || alternative.evidence_type_ids.len() > MAX_EVIDENCE_TYPES_PER_ALTERNATIVE
        {
            findings.push(error_at(
                document,
                "discovery.mapping.evidence-type-count",
                &ids_pointer,
                "an alternative lists 1 to 32 evidence types",
                "List at least one evidence type, and at most 32.",
            ));
        }
        for (position, evidence_type) in alternative.evidence_type_ids.iter().enumerate() {
            identifier(
                &format!("{ids_pointer}/{position}"),
                evidence_type,
                findings,
            );
        }
    }
    findings.diagnostics.len() == before
}

/// Check the `.yaml` and `.yml` files beside `origins.yaml`: each runtime
/// file as `discovery serve` reads it, and a refusal for every other kind.
fn check_root_files(root: &Path, environment: bool, findings: &mut Findings) {
    let Ok(entries) = fs::read_dir(root) else {
        findings.unreadable(root);
        return;
    };
    let mut paths = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            findings.unreadable(root);
            return;
        };
        let path = entry.path();
        if is_yaml(&path) && path.file_name() != Some(ORIGINS_FILE.as_ref()) {
            paths.push(path);
        }
    }
    paths.sort();
    for path in paths {
        let bytes = match contents(&path) {
            Contents::Bytes(bytes) => bytes,
            Contents::Missing | Contents::Unreadable => {
                findings.unreadable(&path);
                continue;
            }
            Contents::NotRegular => {
                findings.about(
                    Severity::Error,
                    "discovery.project.not-a-regular-file",
                    &path,
                    "the file is not a regular file",
                    "Replace the link or directory with a regular file, or move it out of the \
                     project directory.",
                );
                continue;
            }
        };
        let named_runtime = path.file_name() == Some("runtime.yaml".as_ref());
        let tree = Reader::new(path.display().to_string()).scan(&bytes);
        let kind = match &tree {
            Ok(Some(root)) => root.get("kind").and_then(|entry| match &entry.value.value {
                NodeValue::String(text) => Some((text.text.clone(), entry.value.span.start)),
                _ => None,
            }),
            _ => None,
        };
        let (kind, at) = kind.map_or((None, None), |(kind, at)| (Some(kind), Some(at)));
        match (kind.as_deref(), named_runtime, tree) {
            (Some(RUNTIME_KIND), _, _) | (_, true, _) => {
                findings.files += 1;
                check_runtime_file(&path, environment, findings);
            }
            (Some(_), false, _) => {
                findings.files += 1;
                findings.push(foreign_kind(&path, at));
            }
            (None, false, Err(report)) => {
                findings.files += 1;
                findings.extend(report.into_diagnostics());
            }
            (None, false, Ok(_)) => {
                findings.files += 1;
                findings.about(
                    Severity::Warning,
                    "discovery.project.unread-file",
                    &path,
                    "the file names no kind, so the check does not know what it is and did not \
                     read it",
                    "Move it out of the project directory, or give it the apiVersion and kind of \
                     a Discovery runtime file.",
                );
            }
        }
    }
}

fn foreign_kind(path: &Path, at: Option<Position>) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(
        "discovery.project.foreign-kind",
        "/kind",
        "the file is of a kind a Discovery project does not hold; a project holds origins.yaml, \
         the mappings directory, and DiscoveryRuntimeConfig files",
        "Move the file out of the project directory.",
    );
    diagnostic.source = Some(Source {
        file: path.display().to_string(),
        line: at.map(|at| at.line),
        column: at.map(|at| at.column),
    });
    diagnostic
}

/// Check the runtime file at `path` as `discovery serve` reads it, naming
/// the file as it was given.
fn check_runtime_file(path: &Path, environment: bool, findings: &mut Findings) {
    let given = path.display().to_string();
    let Some(absolute) = absolute_lexical(path) else {
        findings.unreadable(path);
        return;
    };
    let checked = check_runtime(&absolute, environment);
    let absolute = absolute.display().to_string();
    findings.unavailable |= checked.unavailable;
    findings.extend(checked.diagnostics.into_iter().map(|mut diagnostic| {
        if let Some(source) = &mut diagnostic.source {
            if source.file == absolute {
                source.file.clone_from(&given);
            }
        }
        for related in &mut diagnostic.related {
            if related.file == absolute {
                related.file.clone_from(&given);
            }
        }
        diagnostic
    }));
}

/// Check one runtime file given on the command line.
#[must_use]
pub fn inspect_runtime_file(path: &Path, environment: bool) -> (Report, bool) {
    let mut findings = Findings {
        files: 1,
        ..Findings::default()
    };
    check_runtime_file(path, environment, &mut findings);
    let unavailable = findings.unavailable;
    (findings.into_report(), unavailable)
}

/// `path` made absolute against the working directory, with `.` and `..`
/// resolved by name, as the runtime loader requires (CFG-ENV-5).
fn absolute_lexical(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    let mut normal = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    Some(normal)
}

fn is_yaml(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("yaml" | "yml")
    )
}

fn valid_catalog_url(value: &str, allow_loopback: bool) -> bool {
    value.chars().count() <= MAX_IDENTIFIER_CHARACTERS
        && registry_discovery_profile::is_valid_endpoint_url(value, allow_loopback)
}

fn valid_origin_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ORIGIN_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_identifier(value: &str) -> bool {
    value.chars().count() <= MAX_IDENTIFIER_CHARACTERS
        && registry_discovery::valid_uri_identifier(value)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    const SUBSTITUTION_NOT_ALLOWED: &str = "config.substitution-not-allowed";

    /// A temporary directory named by its resolved path: the runtime loader
    /// refuses a path through a symbolic link, and macOS reaches its
    /// temporary directory through one.
    fn temporary() -> TempDir {
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory resolves");
        TempDir::new_in(base).expect("temporary directory")
    }

    fn project(origins: &str, mappings: &[(&str, &str)]) -> TempDir {
        let root = temporary();
        fs::write(root.path().join("origins.yaml"), origins).expect("origins");
        fs::create_dir(root.path().join("mappings")).expect("mappings directory");
        for (name, body) in mappings {
            fs::write(root.path().join("mappings").join(name), body).expect("mapping");
        }
        root
    }

    fn refusal(root: &Path) -> Vec<Diagnostic> {
        check_project(root, false)
            .expect_err("the project is refused")
            .report
            .into_diagnostics()
    }

    fn codes(diagnostics: &[Diagnostic]) -> Vec<&str> {
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect()
    }

    fn line_and_column(diagnostic: &Diagnostic) -> (Option<usize>, Option<usize>) {
        let source = diagnostic.source.as_ref().expect("a positioned diagnostic");
        (source.line, source.column)
    }

    const ORIGINS: &str = r#"schemaVersion: registry-discovery/origins/v1alpha1
origins:
  - originId: evidence-one
    catalogUrl: https://unreachable.example.invalid/catalog.jsonld
    profile: registry-discovery-v1alpha1
    enabled: true
"#;

    const MAPPING: &str = r#"schemaVersion: registry-discovery/evidence-mapping/v1alpha1
mappingId: urn:example:mapping:one
mappingAuthorityId: urn:example:authority
requirementId: urn:example:requirement
alternatives:
  - evidenceTypeListId: urn:example:list
    evidenceTypeIds: [urn:example:evidence]
"#;

    #[test]
    fn check_is_offline_and_accepts_an_unreachable_https_origin() {
        let root = project(ORIGINS, &[]);
        let checked = check_project(root.path(), false).expect("offline check");
        assert_eq!(checked.origins.len(), 1);
    }

    #[test]
    fn shipped_authoring_fixture_passes_the_offline_check() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/discovery/fixtures/project");
        let checked = check_project(&root, false).expect("shipped project checks offline");
        assert_eq!(checked.origins.len(), 1);
        assert_eq!(checked.mappings.len(), 1);

        let inspected = inspect_project(&root, ProjectOptions::default());
        assert!(
            inspected.report.is_empty(),
            "{}",
            inspected.report.render_human()
        );
        assert_eq!(inspected.report.files_checked(), Some(3));
        assert!(inspected.project.is_some());
    }

    #[test]
    fn the_tutorial_project_checks_without_its_package_root_variable() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/discovery/tutorial/project");
        let options = ProjectOptions {
            allow_loopback: true,
            environment: false,
        };
        let inspected = inspect_project(&root, options);
        assert!(
            inspected.report.is_empty(),
            "{}",
            inspected.report.render_human()
        );
    }

    #[test]
    fn duplicate_mapping_keys_are_refused() {
        let second = MAPPING.replace("mapping:one", "mapping:two");
        let root = project(ORIGINS, &[("one.yaml", MAPPING), ("two.yaml", &second)]);
        let diagnostics = refusal(root.path());
        assert_eq!(
            codes(&diagnostics),
            ["discovery.project.duplicate-requirement"]
        );
        let diagnostic = &diagnostics[0];
        assert!(diagnostic
            .source
            .as_ref()
            .unwrap()
            .file
            .ends_with("two.yaml"));
        assert_eq!(line_and_column(diagnostic), (Some(4), Some(16)));
        assert_eq!(diagnostic.related.len(), 1);
        assert!(diagnostic.related[0].file.ends_with("one.yaml"));
        assert_eq!(diagnostic.related[0].line, Some(4));

        let root = project(ORIGINS, &[("one.yaml", MAPPING), ("two.yaml", MAPPING)]);
        assert_eq!(
            codes(&refusal(root.path())),
            [
                "discovery.project.duplicate-mapping-id",
                "discovery.project.duplicate-requirement"
            ]
        );
    }

    #[test]
    fn duplicate_origins_point_at_the_first_one() {
        let origins = format!(
            "{ORIGINS}  - originId: evidence-one\n    catalogUrl: https://unreachable.example.invalid/catalog.jsonld\n    profile: registry-discovery-v1alpha1\n    enabled: false\n"
        );
        let root = project(&origins, &[]);
        let diagnostics = refusal(root.path());
        assert_eq!(
            codes(&diagnostics),
            [
                "discovery.origins.duplicate-origin-id",
                "discovery.origins.duplicate-catalog-url"
            ]
        );
        assert_eq!(diagnostics[0].path, "/origins/1/originId");
        assert_eq!(line_and_column(&diagnostics[0]), (Some(7), Some(15)));
        assert_eq!(diagnostics[0].related[0].path, "/origins/0/originId");
        assert_eq!(diagnostics[0].related[0].line, Some(3));
    }

    #[test]
    fn loopback_http_requires_the_explicit_development_switch() {
        for endpoint in [
            "http://localhost:8080/catalog.jsonld",
            "http://127.0.0.1:8080/catalog.jsonld",
            "http://[::1]:8080/catalog.jsonld",
        ] {
            let origins = ORIGINS.replace(
                "https://unreachable.example.invalid/catalog.jsonld",
                endpoint,
            );
            let root = project(&origins, &[]);
            let diagnostics = refusal(root.path());
            assert_eq!(
                codes(&diagnostics),
                ["discovery.origins.catalog-url-not-allowed"],
                "{endpoint}"
            );
            assert!(diagnostics[0].suggested_action.contains("--allow-loopback"));
            assert!(check_project(root.path(), true).is_ok(), "{endpoint}");
        }
    }

    #[test]
    fn catalog_urls_refuse_other_loopbacks_and_preparser_whitespace_or_controls() {
        for endpoint in [
            "http://127.0.0.2:8080/catalog.jsonld",
            "http://127.1:8080/catalog.jsonld",
            "http://LOCALHOST:8080/catalog.jsonld",
            "http://[::2]:8080/catalog.jsonld",
            " https://catalog.example.invalid/catalog.jsonld",
            "https://catalog.example.invalid/catalog.jsonld\n",
            "https://catalog.example.invalid/catalog .jsonld",
            "https://catalog.example.invalid/catalog\u{0007}.jsonld",
        ] {
            assert!(!valid_catalog_url(endpoint, true), "accepted {endpoint:?}");
        }
    }

    #[test]
    fn mapping_semantic_identifiers_accept_rdf_fragment_iris() {
        let mapping = MAPPING.replace("mapping:one", "mapping#fragment");
        let root = project(ORIGINS, &[("fragment.yaml", &mapping)]);
        let checked = check_project(root.path(), false).expect("fragment IRI mapping");
        assert_eq!(
            checked.mappings[0].mapping_id,
            "urn:example:mapping#fragment"
        );
    }

    #[test]
    fn a_mapping_over_the_document_cap_is_refused_as_too_large() {
        let mut mapping = MAPPING.to_owned();
        mapping.push_str(&format!("# {}\n", "x".repeat(MAXIMUM_DOCUMENT_BYTES)));
        let root = project(ORIGINS, &[("large.yaml", &mapping)]);
        assert_eq!(codes(&refusal(root.path())), ["yaml.too-large"]);
    }

    #[test]
    fn cfg_sec_2_authored_files_refuse_substitution_at_its_position() {
        let origins = ORIGINS.replace(
            "https://unreachable.example.invalid/catalog.jsonld",
            "${CATALOG_URL}",
        );
        let mapping = MAPPING.replace("urn:example:authority", "${AUTHORITY}");
        let root = project(&origins, &[("one.yaml", &mapping)]);
        let diagnostics = refusal(root.path());
        assert_eq!(
            codes(&diagnostics),
            [SUBSTITUTION_NOT_ALLOWED, SUBSTITUTION_NOT_ALLOWED]
        );
        assert_eq!(diagnostics[0].path, "/origins/0/catalogUrl");
        assert_eq!(line_and_column(&diagnostics[0]), (Some(4), Some(17)));
        assert_eq!(diagnostics[1].path, "/mappingAuthorityId");
        assert_eq!(line_and_column(&diagnostics[1]), (Some(3), Some(21)));
        for diagnostic in &diagnostics {
            assert!(!diagnostic.message.contains("CATALOG_URL"));
            assert!(!diagnostic.message.contains("AUTHORITY"));
        }
    }

    #[test]
    fn every_unknown_key_is_reported_with_its_position() {
        let origins = ORIGINS
            .replace("catalogUrl:", "catalogURL:")
            .replace("enabled:", "enabled: true\n    disabled:");
        let root = project(&origins, &[]);
        let diagnostics = refusal(root.path());
        let unknown: Vec<_> = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "config.unknown-key")
            .map(|diagnostic| (diagnostic.path.as_str(), line_and_column(diagnostic)))
            .collect();
        assert_eq!(
            unknown,
            [
                ("/origins/0/catalogURL", (Some(4), Some(5))),
                ("/origins/0/disabled", (Some(7), Some(5))),
            ]
        );
        assert!(diagnostics[0].suggested_action.contains("catalogUrl"));
    }

    #[test]
    fn a_wrong_header_null_or_repeated_evidence_type_is_refused() {
        let wrong_header = MAPPING.replace("evidence-mapping/v1alpha1", "evidence-mapping/v2");
        let null_jurisdiction = MAPPING.replace(
            "requirementId: urn:example:requirement\n",
            "requirementId: urn:example:requirement\njurisdiction: null\n",
        );
        let repeated = MAPPING.replace(
            "[urn:example:evidence]",
            "[urn:example:evidence, urn:example:evidence]",
        );
        for (body, code, path) in [
            (wrong_header, "config.unknown-variant", "/schemaVersion"),
            (null_jurisdiction, "config.null-value", "/jurisdiction"),
            (
                repeated,
                "config.duplicate-item",
                "/alternatives/0/evidenceTypeIds/1",
            ),
        ] {
            let root = project(ORIGINS, &[("one.yaml", &body)]);
            let diagnostics = refusal(root.path());
            assert_eq!(codes(&diagnostics), [code], "{body}");
            assert_eq!(diagnostics[0].path, path);
            assert!(diagnostics[0].source.as_ref().unwrap().line.is_some());
        }
    }

    #[test]
    fn value_checks_run_only_on_a_cleanly_decoded_file() {
        let mapping = MAPPING
            .replace("urn:example:list", "not an identifier")
            .replace("alternatives:", "unknownMember: true\nalternatives:");
        let root = project(ORIGINS, &[("one.yaml", &mapping)]);
        assert_eq!(codes(&refusal(root.path())), ["config.unknown-key"]);

        let mapping = MAPPING.replace("urn:example:list", "not an identifier");
        let root = project(ORIGINS, &[("one.yaml", &mapping)]);
        let diagnostics = refusal(root.path());
        assert_eq!(
            codes(&diagnostics),
            ["discovery.mapping.invalid-identifier"]
        );
        assert_eq!(diagnostics[0].path, "/alternatives/0/evidenceTypeListId");
        assert_eq!(line_and_column(&diagnostics[0]), (Some(6), Some(25)));
    }

    #[test]
    fn missing_files_and_stray_entries_name_their_fix() {
        let root = temporary();
        let diagnostics = refusal(root.path());
        assert_eq!(
            codes(&diagnostics),
            [
                "discovery.project.missing-file",
                "discovery.project.missing-file"
            ]
        );

        let root = project(ORIGINS, &[("notes.txt", "text"), ("one.yaml", MAPPING)]);
        let diagnostics = refusal(root.path());
        assert_eq!(
            codes(&diagnostics),
            ["discovery.project.unexpected-mapping-entry"]
        );
        assert!(diagnostics[0]
            .source
            .as_ref()
            .unwrap()
            .file
            .ends_with("notes.txt"));

        let absent = root.path().join("absent");
        let checked = check_project(&absent, false).expect_err("no project");
        assert!(checked.unavailable);
    }

    #[test]
    fn cfg_check_2_the_project_check_reads_every_yaml_file_beside_the_origins() {
        let root = project(ORIGINS, &[("one.yaml", MAPPING)]);
        fs::write(
            root.path().join("runtime.yaml"),
            "apiVersion: registry.registrystack.org/discovery-runtime/v1alpha1\nkind: DiscoveryRuntimeConfig\nlistener:\n  bind: 127.0.0.1:8080\n",
        )
        .unwrap();
        fs::write(
            root.path().join("other.yaml"),
            "apiVersion: id.registrystack.org/formats/breg/registry/v1alpha1\nkind: BRegProject\n",
        )
        .unwrap();
        fs::write(root.path().join("notes.yml"), "title: notes\n").unwrap();
        fs::write(root.path().join("README.md"), "not yaml").unwrap();

        let inspected = inspect_project(root.path(), ProjectOptions::default());
        let diagnostics = inspected.report.diagnostics();
        assert_eq!(
            codes(diagnostics),
            [
                "discovery.project.unread-file",
                "discovery.project.foreign-kind",
                "config.missing-key",
            ]
        );
        assert_eq!(diagnostics[0].severity, Severity::Warning);
        assert_eq!(line_and_column(&diagnostics[1]), (Some(2), Some(7)));
        assert!(diagnostics[2].message.contains("`package`"));
        let runtime = diagnostics[2].source.as_ref().unwrap();
        assert_eq!(
            runtime.file,
            root.path().join("runtime.yaml").display().to_string()
        );
        assert_eq!(inspected.report.files_checked(), Some(5));
        assert!(inspected.project.is_none());
        assert!(!inspected.unavailable);
    }

    #[test]
    fn the_runtime_file_named_on_the_command_line_keeps_its_given_path() {
        let root = temporary();
        let path = root.path().join("nested").join("..").join("runtime.yaml");
        fs::write(
            root.path().join("runtime.yaml"),
            "apiVersion: registry.registrystack.org/discovery-runtime/v1alpha1\nkind: DiscoveryRuntimeConfig\nlistener:\n  bind: 127.0.0.1:8080\n  surprise: true\n",
        )
        .unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        let (report, unavailable) = inspect_runtime_file(&path, false);
        assert!(!unavailable);
        let unknown = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "config.unknown-key")
            .expect("the unknown key is reported");
        assert_eq!(
            unknown.source.as_ref().unwrap().file,
            path.display().to_string()
        );
        assert_eq!(line_and_column(unknown), (Some(5), Some(3)));
    }

    #[test]
    fn the_schema_version_and_profile_spellings_match_their_constants() {
        assert_eq!(
            serde_json::to_value(OriginsSchemaVersion::V1Alpha1).unwrap(),
            ORIGINS_SCHEMA
        );
        assert_eq!(
            serde_json::to_value(MappingSchemaVersion::V1Alpha1).unwrap(),
            MAPPING_SCHEMA
        );
        assert_eq!(
            serde_json::to_value(OriginProfile::RegistryDiscoveryV1Alpha1).unwrap(),
            registry_discovery_profile::PROFILE_ID
        );
    }
}
