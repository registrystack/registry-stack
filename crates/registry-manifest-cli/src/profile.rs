// SPDX-License-Identifier: Apache-2.0
//! Reading the profile descriptors (`manifest/profile`) under a profiles
//! directory, and checking each descriptor's fixtures against the
//! expectations it declares.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use registry_manifest_core::{EntityManifest, MetadataManifest};
use registry_platform_yaml::{
    BoundedU32, Diagnostic, Document, Expect, LocalId, Reader, Related, Report, Severity, Url,
};
use serde::Deserialize;

use crate::{
    about, contents, read_metadata, Contents, Findings, PROFILE_FILE_NAME, PROFILE_FORMAT,
};

/// A profile descriptor: the portable expectations one application profile
/// places on the metadata manifests that claim it, and the fixtures that
/// demonstrate them.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ProfileDescriptor {
    /// The descriptor format version.
    pub schema_version: ProfileSchemaVersion,
    /// The profile this descriptor describes.
    pub profile: ProfileIdentity,
    /// The artifacts the profile reads. At least one.
    pub supported_input_artifacts: Vec<InputArtifact>,
    /// Concept IRIs a claiming manifest's fields must reference.
    #[serde(default)]
    pub required_concepts: Vec<ConceptExpectation>,
    /// Concept IRIs a claiming manifest may reference. Documentation only.
    #[serde(default)]
    pub optional_concepts: Vec<ConceptExpectation>,
    /// Identifiers a claiming manifest's entities must declare.
    #[serde(default)]
    pub required_identifiers: Vec<IdentifierExpectation>,
    /// How many times a field occurs in an entity of a claiming manifest.
    #[serde(default)]
    pub cardinality_expectations: Vec<CardinalityExpectation>,
    /// Codes a codelist of a claiming manifest must hold.
    #[serde(default)]
    pub codelist_expectations: Vec<CodelistExpectation>,
    /// Upstream behavior the profile deliberately does not map, and why.
    #[serde(default)]
    pub unsupported_mappings: Vec<UnsupportedMapping>,
    /// The checks the profile names. At least one.
    pub conformance_checks: Vec<ConformanceCheck>,
    /// Metadata manifests that claim the profile and meet every expectation.
    /// At least one.
    pub fixtures: Vec<ProfileFixture>,
}

/// The descriptor format version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProfileSchemaVersion {
    #[serde(rename = "registry-manifest-profile/v1")]
    V1,
}

/// The profile a descriptor describes.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ProfileIdentity {
    /// The profile id. It names the directory that holds the descriptor, and
    /// a claiming manifest lists it under `profiles`.
    pub id: LocalId,
    /// The profile version a claiming manifest lists beside the id.
    pub version: String,
    pub name: Option<String>,
    pub upstream_system: Option<String>,
    pub upstream_url: Option<Url>,
    pub description: Option<String>,
}

/// An artifact the profile reads.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct InputArtifact {
    pub kind: String,
    pub media_type: Option<String>,
    pub description: Option<String>,
}

/// A concept a claiming manifest's fields reference by IRI.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ConceptExpectation {
    pub name: Option<String>,
    /// The IRI, exactly as a field's `concepts` lists it.
    pub iri: String,
}

/// An identifier a claiming manifest's entity declares.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct IdentifierExpectation {
    pub entity: String,
    pub name: String,
    pub kind: String,
}

/// How many times a field occurs in an entity. A field name occurs at most
/// once in an entity, so both bounds are 0 or 1, and `min` is at most `max`.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CardinalityExpectation {
    pub entity: String,
    pub field: String,
    pub min: BoundedU32<0, 1>,
    pub max: BoundedU32<0, 1>,
}

/// Codes a codelist holds.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CodelistExpectation {
    pub id: String,
    pub required_codes: Vec<String>,
}

/// Upstream behavior the profile does not map.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UnsupportedMapping {
    pub source: String,
    pub reason: String,
}

/// A check the profile names. Descriptive: `validate-profiles` runs the
/// expectations above, not these entries.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ConformanceCheck {
    pub id: String,
    pub severity: Option<CheckSeverity>,
    pub description: Option<String>,
}

/// How serious a failed conformance check is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum CheckSeverity {
    Error,
    Warning,
}

/// A metadata manifest that demonstrates the profile.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ProfileFixture {
    /// The fixture's path, relative to the descriptor's directory and inside
    /// it.
    pub path: String,
    /// Whether the fixture is a metadata manifest. Descriptive.
    pub manifest: Option<bool>,
    /// The outcome the fixture demonstrates. Descriptive.
    pub expect: Option<FixtureExpectation>,
    pub description: Option<String>,
}

/// The outcome a fixture demonstrates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum FixtureExpectation {
    Valid,
}

/// What `validate-profiles` found under one profiles directory.
pub struct ProfilesCheck {
    /// The descriptors found.
    pub profiles: usize,
    pub report: Report,
    /// A file or directory could not be read, so the check is incomplete.
    pub unavailable: bool,
}

/// Check every `<profile>/profile.yaml` under `root` and every fixture each
/// lists. A YAML file under `root` that is neither a descriptor nor a
/// listed fixture is reported as a warning (CFG-CHECK-2).
pub fn check_profiles(root: &Path) -> ProfilesCheck {
    let mut findings = Findings::default();
    let descriptors = match descriptor_paths(root) {
        Ok(descriptors) => descriptors,
        Err(()) => {
            unreadable_directory(&mut findings, root);
            return finish(findings, 0);
        }
    };
    if descriptors.is_empty() {
        findings.push(about(
            Severity::Error,
            "manifest.profile.no-descriptors",
            root,
            "the profiles directory holds no profile descriptor",
            "Add a directory per profile holding its profile.yaml, or pass the profiles \
             directory that holds them.",
        ));
        return finish(findings, 0);
    }
    let mut known = BTreeSet::new();
    for descriptor in &descriptors {
        known.insert(normalized(descriptor));
        check_descriptor(&mut findings, descriptor, &mut known);
    }
    unlisted_files(&mut findings, root, &known);
    finish(findings, descriptors.len())
}

fn finish(findings: Findings, profiles: usize) -> ProfilesCheck {
    let (report, unavailable) = findings.into_report();
    ProfilesCheck {
        profiles,
        report,
        unavailable,
    }
}

fn unreadable_directory(findings: &mut Findings, root: &Path) {
    match fs::metadata(root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => findings.unreadable(
            "manifest.profile.missing-directory",
            root,
            "the profiles directory does not exist",
            "Pass the path of an existing profiles directory.",
        ),
        Ok(metadata) if !metadata.is_dir() => findings.unreadable(
            "manifest.profile.not-a-directory",
            root,
            "the profiles path is not a directory",
            "Pass the directory that holds one directory per profile.",
        ),
        _ => findings.unreadable(
            "manifest.profile.unreadable",
            root,
            "the profiles directory cannot be listed by this process",
            "Give this process permission to list and read the profiles directory.",
        ),
    }
}

/// `root/<child>/profile.yaml` for every child directory that holds one,
/// sorted.
fn descriptor_paths(root: &Path) -> Result<Vec<PathBuf>, ()> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| ())? {
        let path = entry.map_err(|_| ())?.path().join(PROFILE_FILE_NAME);
        if path.is_file() {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// Check one descriptor and its fixtures. `known` gains every fixture the
/// descriptor lists or, when the descriptor cannot be read, its whole
/// directory: the refusal already names it, so its files are not reported
/// as unlisted.
fn check_descriptor(findings: &mut Findings, path: &Path, known: &mut BTreeSet<PathBuf>) {
    let directory = path.parent().unwrap_or(Path::new(""));
    let bytes = match contents(path) {
        Contents::Bytes(bytes) => bytes,
        Contents::Missing | Contents::Unreadable => {
            findings.unreadable(
                "manifest.profile.unreadable",
                path,
                "the profile descriptor cannot be read by this process",
                "Give this process permission to read the profile descriptor.",
            );
            known.insert(normalized(directory));
            return;
        }
    };
    findings.files += 1;
    let mut hook = registry_platform_config::AuthoredExpressions;
    let decoded = Reader::new(path.display().to_string())
        .with_hook(&mut hook)
        .decode::<ProfileDescriptor>(&bytes, &Expect::one(&PROFILE_FORMAT));
    let (document, descriptor) = match decoded {
        Ok(decoded) => (decoded.document, decoded.value),
        Err(report) => {
            findings.extend(report.into_diagnostics());
            known.insert(normalized(directory));
            return;
        }
    };
    findings.extend(document.warnings().into_diagnostics());
    for fixture in &descriptor.fixtures {
        if let Some(relative) = contained(&fixture.path) {
            known.insert(normalized(&directory.join(relative)));
        }
    }
    let refused = descriptor_findings(&document, directory, &descriptor);
    let refused_count = refused.len();
    findings.extend(refused);
    if refused_count > 0 {
        return;
    }
    for (index, fixture) in descriptor.fixtures.iter().enumerate() {
        check_fixture(findings, &document, directory, &descriptor, index, fixture);
    }
}

/// The descriptor's own rules, beyond its shape.
fn descriptor_findings(
    document: &Document,
    directory: &Path,
    descriptor: &ProfileDescriptor,
) -> Vec<Diagnostic> {
    let mut found = Vec::new();
    if descriptor.profile.version.trim().is_empty() {
        found.push(document.diagnostic_at_value(
            Severity::Error,
            "manifest.profile.empty-value",
            "/profile/version",
            "the profile version is empty",
            "Write the profile version a claiming manifest lists beside the profile id.",
        ));
    }
    let directory_name = directory.file_name().and_then(|name| name.to_str());
    if directory_name != Some(descriptor.profile.id.as_str()) {
        found.push(document.diagnostic_at_value(
            Severity::Error,
            "manifest.profile.id-mismatch",
            "/profile/id",
            "the profile id differs from the name of the directory that holds the descriptor",
            "Rename the directory to the profile id, or set the profile id to the directory \
             name.",
        ));
    }
    for (member, list_len) in [
        (
            "supported_input_artifacts",
            descriptor.supported_input_artifacts.len(),
        ),
        ("conformance_checks", descriptor.conformance_checks.len()),
        ("fixtures", descriptor.fixtures.len()),
    ] {
        if list_len == 0 {
            found.push(document.diagnostic_at_value(
                Severity::Error,
                "manifest.profile.empty-list",
                &format!("/{member}"),
                "this list needs at least one entry",
                "Add at least one entry to the list.",
            ));
        }
    }
    for (index, expected) in descriptor.cardinality_expectations.iter().enumerate() {
        if expected.min.get() > expected.max.get() {
            found.push(document.diagnostic_at_value(
                Severity::Error,
                "manifest.profile.invalid-range",
                &format!("/cardinality_expectations/{index}"),
                "min is greater than max",
                "Set min to a value no greater than max.",
            ));
        }
    }
    for (index, fixture) in descriptor.fixtures.iter().enumerate() {
        let pointer = format!("/fixtures/{index}/path");
        if fixture.path.trim().is_empty() {
            found.push(document.diagnostic_at_value(
                Severity::Error,
                "manifest.profile.empty-value",
                &pointer,
                "the fixture path is empty",
                "Write the fixture's path relative to the descriptor's directory.",
            ));
        } else if contained(&fixture.path).is_none() {
            found.push(document.diagnostic_at_value(
                Severity::Error,
                "manifest.profile.fixture-path-escapes",
                &pointer,
                "the fixture path is absolute or climbs out of the descriptor's directory",
                "Write the fixture's path relative to the descriptor's directory, without `..` \
                 segments.",
            ));
        }
    }
    found
}

/// The path, when it is relative and stays inside the directory it is
/// relative to.
fn contained(path: &str) -> Option<&Path> {
    let path = Path::new(path);
    path.components()
        .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
        .then_some(path)
}

/// Where a listed fixture leads once every link is followed.
enum Resolved {
    /// Inside the descriptor's directory: the path with no link left in it.
    Inside(PathBuf),
    /// Outside the descriptor's directory (CFG-VAL-8).
    Outside,
    /// Nothing at the path; reading it reports the file as missing or
    /// unreadable.
    Unresolved,
}

/// Follow every link in `path` and say whether it ends inside `directory`.
/// The fixture is then read at the resolved path, so a link changed after
/// this check cannot lead the read elsewhere.
fn resolved_inside(directory: &Path, path: &Path) -> Resolved {
    match (fs::canonicalize(directory), fs::canonicalize(path)) {
        (Ok(directory), Ok(path)) if path.starts_with(&directory) => Resolved::Inside(path),
        (Ok(_), Ok(_)) => Resolved::Outside,
        _ => Resolved::Unresolved,
    }
}

/// A path with its `.` segments removed, for comparing listed fixtures.
fn normalized(path: &Path) -> PathBuf {
    path.components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect()
}

fn check_fixture(
    findings: &mut Findings,
    document: &Document,
    directory: &Path,
    descriptor: &ProfileDescriptor,
    index: usize,
    fixture: &ProfileFixture,
) {
    let path = directory.join(&fixture.path);
    let resolved = match resolved_inside(directory, &path) {
        Resolved::Inside(resolved) => resolved,
        Resolved::Unresolved => path.clone(),
        Resolved::Outside => {
            findings.push(document.diagnostic_at_value(
                Severity::Error,
                "manifest.profile.fixture-path-escapes",
                &format!("/fixtures/{index}/path"),
                "the fixture path leads through a link to a file outside the descriptor's \
                 directory",
                "Put the fixture itself at the listed path, or point the link at a file inside \
                 the descriptor's directory.",
            ));
            return;
        }
    };
    let bytes = match contents(&resolved) {
        Contents::Bytes(bytes) => bytes,
        Contents::Missing => {
            findings.push(document.diagnostic_at_value(
                Severity::Error,
                "manifest.profile.missing-fixture",
                &format!("/fixtures/{index}/path"),
                "the fixture this entry lists does not exist",
                "Add the fixture at the listed path, or list the path of an existing fixture.",
            ));
            return;
        }
        Contents::Unreadable => {
            findings.unreadable(
                "manifest.profile.unreadable",
                &path,
                "the fixture is not a regular file this process can read",
                "Make the fixture a regular file, and give this process permission to read it.",
            );
            return;
        }
    };
    findings.files += 1;
    let fixture_file = path.display().to_string();
    let read = match read_metadata(&fixture_file, &bytes) {
        Ok(read) => read,
        Err(diagnostics) => {
            findings.extend(diagnostics);
            return;
        }
    };
    findings.extend(read.document.warnings().into_diagnostics());
    let related = Related {
        file: fixture_file,
        line: None,
        column: None,
        path: String::new(),
        message: "the fixture checked against this expectation".to_owned(),
    };
    for mut diagnostic in expectation_findings(document, descriptor, &read.manifest) {
        diagnostic.related.push(related.clone());
        findings.push(diagnostic);
    }
}

/// Every expectation of the descriptor the fixture does not meet, placed at
/// the expectation in the descriptor.
fn expectation_findings(
    document: &Document,
    descriptor: &ProfileDescriptor,
    manifest: &MetadataManifest,
) -> Vec<Diagnostic> {
    let mut found = Vec::new();
    let mut at = |pointer: &str, code: &str, message: &str, action: &str| {
        found.push(document.diagnostic_at_value(Severity::Error, code, pointer, message, action));
    };
    let claimed = manifest.profiles.iter().any(|claim| {
        claim.id == descriptor.profile.id.as_str() && claim.version == descriptor.profile.version
    });
    if !claimed {
        at(
            "/profile",
            "manifest.profile.claim-missing",
            "the fixture does not list this profile's id and version under profiles",
            "Add the profile's id and version to the fixture's profiles list.",
        );
    }
    let concepts = manifest_concepts(manifest);
    for (index, required) in descriptor.required_concepts.iter().enumerate() {
        if !concepts.contains(required.iri.as_str()) {
            at(
                &format!("/required_concepts/{index}/iri"),
                "manifest.profile.required-concept-missing",
                "no field of the fixture references this concept",
                "Reference the concept from a field's concepts list in the fixture.",
            );
        }
    }
    let entities = manifest_entities(manifest);
    let entity = |name: &str| entities.iter().find(|entity| entity.name == name);
    for (index, required) in descriptor.required_identifiers.iter().enumerate() {
        let declared = entity(&required.entity).is_some_and(|entity| {
            entity.identifiers.iter().any(|identifier| {
                identifier.name == required.name && identifier.kind == required.kind
            })
        });
        if !declared {
            at(
                &format!("/required_identifiers/{index}"),
                "manifest.profile.identifier-missing",
                "the fixture's entity does not declare this identifier with this kind",
                "Declare the identifier, with the expected name and kind, on the fixture's \
                 entity.",
            );
        }
    }
    for (index, expected) in descriptor.cardinality_expectations.iter().enumerate() {
        let count = entity(&expected.entity).map_or(0, |entity| {
            entity
                .fields
                .iter()
                .filter(|field| field.name == expected.field)
                .count()
        });
        let within = (expected.min.get() as usize..=expected.max.get() as usize).contains(&count);
        if !within {
            at(
                &format!("/cardinality_expectations/{index}"),
                "manifest.profile.cardinality-mismatch",
                "the fixture's entity holds this field a number of times outside the expected \
                 bounds",
                "Add or remove the field on the fixture's entity until it occurs within min and \
                 max.",
            );
        }
    }
    let codelists = manifest_codelists(manifest);
    for (index, expected) in descriptor.codelist_expectations.iter().enumerate() {
        let Some(codes) = codelists.get(expected.id.as_str()) else {
            at(
                &format!("/codelist_expectations/{index}/id"),
                "manifest.profile.codelist-mismatch",
                "the fixture declares no codelist with this id",
                "Declare the codelist, with every required code, in the fixture.",
            );
            continue;
        };
        for (code_index, code) in expected.required_codes.iter().enumerate() {
            if !codes.contains(code.as_str()) {
                at(
                    &format!("/codelist_expectations/{index}/required_codes/{code_index}"),
                    "manifest.profile.codelist-mismatch",
                    "the fixture's codelist does not hold this code",
                    "Add the code to the fixture's codelist.",
                );
            }
        }
    }
    found
}

fn manifest_entities(manifest: &MetadataManifest) -> Vec<&EntityManifest> {
    manifest
        .datasets
        .iter()
        .flat_map(|dataset| dataset.entities.iter())
        .collect()
}

fn manifest_concepts(manifest: &MetadataManifest) -> BTreeSet<&str> {
    manifest_entities(manifest)
        .into_iter()
        .flat_map(|entity| entity.fields.iter())
        .flat_map(|field| field.concepts.iter().map(String::as_str))
        .collect()
}

fn manifest_codelists(manifest: &MetadataManifest) -> BTreeMap<&str, BTreeSet<&str>> {
    manifest
        .codelists
        .iter()
        .map(|codelist| {
            (
                codelist.id.as_str(),
                codelist
                    .concepts
                    .iter()
                    .map(|concept| concept.code.as_str())
                    .collect(),
            )
        })
        .collect()
}

/// Warn about every YAML file under `root` that is neither a descriptor nor
/// a listed fixture. Linked directories are not followed.
fn unlisted_files(findings: &mut Findings, root: &Path, known: &BTreeSet<PathBuf>) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            findings.unreadable(
                "manifest.profile.unreadable",
                &directory,
                "a directory under the profiles directory cannot be listed by this process",
                "Give this process permission to list every directory under the profiles \
                 directory.",
            );
            continue;
        };
        let mut paths = entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_type().ok().map(|kind| (entry.path(), kind)))
            .collect::<Vec<_>>();
        paths.sort_by(|left, right| left.0.cmp(&right.0));
        for (path, kind) in paths {
            if kind.is_dir() {
                pending.push(path);
                continue;
            }
            let yaml = path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| matches!(extension, "yaml" | "yml"));
            let listed = path
                .ancestors()
                .any(|listed| known.contains(&normalized(listed)));
            if yaml && !listed {
                findings.push(about(
                    Severity::Warning,
                    "manifest.profile.unlisted-file",
                    &path,
                    "this YAML file is neither a profile descriptor nor a fixture a descriptor \
                     lists, so no check reads it",
                    "List the file under its descriptor's fixtures, or move it out of the \
                     profiles directory.",
                ));
            }
        }
    }
}
