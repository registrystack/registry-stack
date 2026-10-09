// SPDX-License-Identifier: Apache-2.0

//! Reading an authored package from disk and computing its digest.
//!
//! A package root holds `messaging.yaml` and, when it ships templates, a
//! `templates/` tree laid out as `<id>/<version>/` directories. Each version
//! directory holds `template.yaml`, `schema.json`, an optional
//! `sample.json`, and one directory per locale holding the part sources
//! `subject.j2`, `text.j2`, and `html.j2`.
//!
//! Every provider the manifest declares with type `http` has a
//! `providers/<id>/` directory holding `provider.yaml`, the provider's
//! package half, and exactly the scripts it names, at the paths it names
//! relative to that directory. No other directory may appear under
//! `providers/`: an `smtp` provider has no package files.
//!
//! Nothing else may appear under `templates/` or `providers/`: an unknown
//! entry, a hidden file, or a symbolic link is refused rather than skipped,
//! so what the runtime reads is exactly what the author sees. Other entries
//! beside `messaging.yaml` at the root, such as a README or the runtime
//! example, are not package content and are neither read nor digested.
//!
//! `messagingctl package` writes those authored inputs into the shared
//! immutable package envelope. The runtime verifies `SHA256SUMS`, optional
//! revision metadata, and every consumed file before parsing product data.
//! Changing, adding, removing, or swapping any installed package byte is
//! therefore refused.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::Path;

use registry_messaging_core::{
    CompiledTemplate, FindingReason, LocaleSources, MessagingFinding, MessagingProject, Package,
    PackageError, PartKind, ProviderKind, TemplateDocument, TemplateReference, TemplateSource,
    MAXIMUM_TEMPLATE_SOURCE_BYTES, MESSAGING_PROJECT_KIND, MESSAGING_PROVIDER_KIND,
    MESSAGING_TEMPLATE_KIND, PACKAGE_FILE,
};
use registry_platform_config::package::is_envelope_file;
use registry_platform_config::{
    plan_package, verify_package, write_package, AuthoredExpressions, PackageConfig,
    PackageError as SharedPackageError, PackageErrorKind as SharedPackageErrorKind, PackageLimits,
    VerifiedPackage, REVISION_FILE, SUM_FILE,
};
use registry_platform_yaml::{
    Decoded, Diagnostic, Document, Reader, Report, Severity, Source, MAXIMUM_DOCUMENT_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::http_provider::{
    script_findings, HttpProviderPackage, HttpProviderScripts, ReceiptCapability,
    MAXIMUM_SCRIPT_SOURCE_BYTES,
};

/// The directory under the package root holding every template version.
pub const TEMPLATES_DIRECTORY: &str = "templates";
/// A template version's descriptor.
pub const TEMPLATE_FILE: &str = "template.yaml";
/// A template version's data schema.
pub const SCHEMA_FILE: &str = "schema.json";
/// A template version's optional sample data, checked against the schema
/// and rendered in every locale when the package loads.
pub const SAMPLE_FILE: &str = "sample.json";

/// The directory under the package root holding every HTTP provider's
/// package half.
pub const PROVIDERS_DIRECTORY: &str = "providers";
/// An HTTP provider's package half, under `providers/<id>/`.
pub const PROVIDER_FILE: &str = "provider.yaml";

/// The largest `messaging.yaml` the runtime reads.
pub const MAXIMUM_MANIFEST_BYTES: u64 = 1024 * 1024;
/// The largest `template.yaml` and `provider.yaml`: the shared reader's bound
/// (CFG-YAML-6), with no lower bound of the package's own.
pub const MAXIMUM_YAML_FILE_BYTES: u64 = MAXIMUM_DOCUMENT_BYTES as u64;
/// The largest locale text, `schema.json` and `sample.json` under `templates/`.
pub const MAXIMUM_TEMPLATE_FILE_BYTES: u64 = MAXIMUM_TEMPLATE_SOURCE_BYTES as u64;
// An authored YAML file's bound may lower the shared reader's, never raise it.
const _: () = assert!(MAXIMUM_MANIFEST_BYTES <= MAXIMUM_DOCUMENT_BYTES as u64);
const _: () = assert!(MAXIMUM_TEMPLATE_FILE_BYTES <= MAXIMUM_DOCUMENT_BYTES as u64);
/// The most directory entries a package may hold under `templates/` and
/// `providers/` together.
pub const MAXIMUM_PACKAGE_ENTRIES: usize = 4096;
/// The most bytes all package files may hold together.
pub const MAXIMUM_PACKAGE_BYTES: u64 = 32 * 1024 * 1024;
const MAXIMUM_ENVELOPE_BYTES: u64 = 4 * 1024 * 1024;

/// Remediation named by shared package refusals.
pub const PACKAGE_COMMAND: &str = "registry-messagingctl package";

#[must_use]
pub const fn package_limits() -> PackageLimits {
    PackageLimits {
        max_files: MAXIMUM_PACKAGE_ENTRIES,
        max_file_bytes: MAXIMUM_MANIFEST_BYTES,
        max_total_bytes: MAXIMUM_PACKAGE_BYTES,
        max_depth: 16,
        max_path_bytes: 512,
    }
}

/// One file the digest covers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageFile {
    /// The `/`-separated path under the package root.
    pub path: String,
    /// `sha256:<hex>` of the file's bytes.
    pub sha256: String,
    pub bytes: u64,
}

/// A package read from disk: the checked package, the package half of every
/// HTTP provider by provider id, the files its digest covers, sorted by
/// path, and the warnings its files hold.
#[derive(Clone, Debug)]
pub struct LoadedPackage {
    pub package: Package,
    pub providers: BTreeMap<String, HttpProviderSource>,
    pub files: Vec<PackageFile>,
    warnings: Report,
    inputs: BTreeMap<String, Vec<u8>>,
}

impl LoadedPackage {
    /// What reading the package's authored files found that does not refuse
    /// it: every warning, placed in its file.
    #[must_use]
    pub const fn warnings(&self) -> &Report {
        &self.warnings
    }

    /// The providers whose package half declares `receipts: callback`: the
    /// ones whose delivery receipts the runtime records. Every other
    /// provider's messages report `unavailable`.
    #[must_use]
    pub fn receipt_providers(&self) -> BTreeSet<String> {
        self.providers
            .iter()
            .filter(|(_, source)| {
                source.package.capabilities.receipts == ReceiptCapability::Callback
            })
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// One HTTP provider's package half as read from `providers/<id>/`: its
/// checked `provider.yaml` and the sources of the scripts it names, each of
/// which compiled when the package loaded.
#[derive(Clone)]
pub struct HttpProviderSource {
    pub package: HttpProviderPackage,
    prepare: String,
    interpret: Option<String>,
    receipt: Option<String>,
}

impl HttpProviderSource {
    /// The script sources, as activation takes them.
    #[must_use]
    pub fn scripts(&self) -> HttpProviderScripts<'_> {
        HttpProviderScripts {
            prepare: &self.prepare,
            interpret: self.interpret.as_deref(),
            receipt: self.receipt.as_deref(),
        }
    }
}

impl std::fmt::Debug for HttpProviderSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpProviderSource")
            .field("package", &self.package)
            .finish_non_exhaustive()
    }
}

/// Why a package could not be loaded, and where.
#[derive(Debug, Error)]
#[error("{path} {reason}")]
pub struct PackageLoadError {
    path: String,
    reason: PackageLoadReason,
}

impl PackageLoadError {
    fn new(file: &str, reason: PackageLoadReason) -> Self {
        let path = if file.is_empty() {
            "package.root".to_owned()
        } else {
            format!("package.root/{file}")
        };
        Self { path, reason }
    }

    fn envelope(error: SharedPackageError) -> Self {
        // The shared refusal repeats the pin as written; this one names only
        // the digest computed from the package, which the pin is compared to.
        if let SharedPackageErrorKind::DigestMismatch(mismatch) = error.kind() {
            return Self {
                path: "package.expectedDigest".to_owned(),
                reason: PackageLoadReason::DigestMismatch {
                    found: mismatch.found.clone(),
                },
            };
        }
        Self {
            path: "package.root".to_owned(),
            reason: PackageLoadReason::Envelope(Box::new(error)),
        }
    }

    /// The refused entry, written `package.root/<path>`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn reason(&self) -> &PackageLoadReason {
        &self.reason
    }

    /// Every diagnostic the package's authored files hold, placed in its
    /// file, when reading them refused the package.
    #[must_use]
    pub const fn report(&self) -> Option<&Report> {
        match &self.reason {
            PackageLoadReason::Refused(report) => Some(report),
            _ => None,
        }
    }

    /// Whether the package could not be read at all, rather than read and
    /// refused.
    #[must_use]
    pub fn is_read_failure(&self) -> bool {
        matches!(self.reason, PackageLoadReason::Read(_))
            || matches!(
                self.reason,
                PackageLoadReason::Envelope(ref error)
                    if matches!(
                        error.kind(),
                        SharedPackageErrorKind::RootInvalid { .. }
                            | SharedPackageErrorKind::Io { .. }
                    )
            )
    }
}

#[derive(Debug, Error)]
pub enum PackageLoadReason {
    #[error("does not satisfy the shared package envelope: {0}")]
    Envelope(#[source] Box<SharedPackageError>),
    /// The authored files the package holds were read and refused: the
    /// report places every diagnostic in its file.
    #[error("is refused: {}", first_error(.0))]
    Refused(Report),
    #[error(
        "does not pin the package at package.root, whose digest is {found}; \
         deploy the pinned package or update package.expectedDigest"
    )]
    DigestMismatch { found: String },
    #[error("changed after its package digest was verified")]
    Changed,
    #[error("could not be read")]
    Read(#[source] std::io::Error),
    #[error("is not part of the package layout")]
    Unexpected,
    #[error("is a symbolic link, which a package may not contain")]
    Symlink,
    #[error("exceeds {0} bytes")]
    FileTooLarge(u64),
    #[error("holds more than {MAXIMUM_PACKAGE_ENTRIES} entries under templates and providers")]
    TooManyEntries,
    #[error("holds more than {MAXIMUM_PACKAGE_BYTES} bytes of package files")]
    TooLarge,
    #[error("is not UTF-8 text")]
    NotUtf8,
    #[error("is refused: {0}")]
    Invalid(PackageError),
}

fn first_error(report: &Report) -> &str {
    report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.severity == Severity::Error)
        .map_or("the package does not pass its checks", |diagnostic| {
            diagnostic.message.as_str()
        })
}

/// Verify and load the installed package under `root`.
pub fn load_package(root: &Path) -> Result<LoadedPackage, PackageLoadError> {
    let verified = verify_package(root, &package_limits(), PACKAGE_COMMAND)
        .map_err(PackageLoadError::envelope)?;
    load_contents(root, Some(&verified))
}

/// Verify the runtime package and its optional configured digest pin before
/// parsing any product file.
pub fn load_runtime_package(config: &PackageConfig) -> Result<LoadedPackage, PackageLoadError> {
    let verified = config
        .verify_package(&package_limits(), PACKAGE_COMMAND)
        .map_err(PackageLoadError::envelope)?;
    load_contents(&config.root, Some(&verified))
}

/// Load and validate an editable authoring project before it is packaged.
pub fn load_project(root: &Path) -> Result<LoadedPackage, PackageLoadError> {
    load_contents(root, None)
}

/// Validate an editable authoring project and return exactly the files copied
/// into an installed package. Runtime settings, secrets, tool state and root
/// documentation are never package inputs.
pub fn package_inputs(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, PackageLoadError> {
    let loaded = load_project(root)?;
    Ok(loaded.inputs)
}

/// Compute the shared package digest for validated inputs without writing.
pub fn plan_package_inputs(
    project: &Path,
    inputs: &BTreeMap<String, Vec<u8>>,
    revision: Option<&str>,
) -> Result<String, SharedPackageError> {
    plan_package(
        project,
        inputs,
        revision,
        &package_limits(),
        PACKAGE_COMMAND,
    )
}

/// Write validated inputs as a new shared package directory.
pub fn write_package_inputs(
    output: &Path,
    inputs: &BTreeMap<String, Vec<u8>>,
    revision: Option<&str>,
) -> Result<VerifiedPackage, SharedPackageError> {
    write_package(output, inputs, revision, &package_limits(), PACKAGE_COMMAND)
}

fn load_contents(
    root: &Path,
    verified: Option<&VerifiedPackage>,
) -> Result<LoadedPackage, PackageLoadError> {
    if let Some(verified) = verified {
        rebind_envelope(root, verified)?;
    }
    let mut reader = PackageReader {
        root,
        verified,
        files: Vec::new(),
        inputs: BTreeMap::new(),
        bytes: 0,
        entries: 0,
        found: Found::default(),
    };
    let project = reader
        .read_document(PACKAGE_FILE, MESSAGING_PROJECT_KIND, MAXIMUM_MANIFEST_BYTES)?
        .and_then(|bytes| reader.decode(PACKAGE_FILE, &bytes, MessagingProject::decode));
    if let Some(project) = &project {
        reader
            .found
            .note_findings(PACKAGE_FILE, &project.document, &project.value.findings());
    }
    let (templates, shipped) = reader.read_templates()?;
    let mut compiled = Vec::new();
    for (source, document, path) in templates {
        let reference = TemplateReference {
            id: source.id.clone(),
            version: source.version.clone(),
        };
        let findings = match &project {
            Some(project) if !project.value.declares_template(&reference) => {
                vec![MessagingFinding::new(FindingReason::UndeclaredTemplate, "")]
            }
            _ => match CompiledTemplate::compile(source) {
                Ok(template) => {
                    compiled.push(template);
                    Vec::new()
                }
                Err(finding) => vec![finding],
            },
        };
        reader.found.note_findings(&path, &document, &findings);
    }
    let providers = match &project {
        Some(project) => {
            let http_providers: BTreeSet<String> = project
                .value
                .providers
                .iter()
                .filter(|provider| provider.kind == ProviderKind::Http)
                .map(|provider| provider.id.clone())
                .collect();
            reader.read_providers(&http_providers)?
        }
        None => BTreeMap::new(),
    };
    if let Some(project) = &project {
        let missing = project.value.missing_templates(&shipped);
        for finding in &missing {
            let placed = finding.to_diagnostic(&project.document);
            reader.found.note(PACKAGE_FILE, Report::new(vec![placed]));
        }
    }
    let mut found = std::mem::take(&mut reader.found);
    found.report.set_files_checked(reader.files.len());
    let Some(project) = project.filter(|_| !found.report.has_errors()) else {
        return Err(found.refusal());
    };
    if let Some(verified) = verified {
        if let Some(unread) = verified
            .files()
            .find(|path| !is_envelope_file(path) && !reader.inputs.contains_key(*path))
        {
            return Err(PackageLoadError::new(unread, PackageLoadReason::Unexpected));
        }
    }
    let mut files = reader.files;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let digest = match verified {
        Some(verified) => verified.digest().to_owned(),
        None => plan_package(
            root,
            &reader.inputs,
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .map_err(|error| PackageLoadError::new("", PackageLoadReason::Envelope(Box::new(error))))?,
    };
    let package = Package::assemble(&project.value, compiled, digest)
        .map_err(|error| PackageLoadError::new(PACKAGE_FILE, PackageLoadReason::Invalid(error)))?;
    Ok(LoadedPackage {
        package,
        providers,
        files,
        warnings: found.report,
        inputs: reader.inputs,
    })
}

/// What reading the package's authored files found: every diagnostic, file
/// by file, and the first file holding an error.
#[derive(Default)]
struct Found {
    report: Report,
    refused: Option<String>,
}

impl Found {
    fn note(&mut self, file: &str, report: Report) {
        if self.refused.is_none() && report.has_errors() {
            self.refused = Some(file.to_owned());
        }
        self.report.extend(report);
    }

    /// Note the document's warnings and every finding placed in it, each
    /// under the file it names: `path` itself, or a file beside it.
    fn note_findings(&mut self, path: &str, document: &Document, findings: &[MessagingFinding]) {
        self.note(path, document.warnings());
        let directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
        for finding in findings {
            let file = match &finding.file {
                Some(file) if directory.is_empty() => file.clone(),
                Some(file) => format!("{directory}/{file}"),
                None => path.to_owned(),
            };
            self.note(&file, Report::new(vec![finding.to_diagnostic(document)]));
        }
    }

    fn refusal(self) -> PackageLoadError {
        PackageLoadError::new(
            self.refused.as_deref().unwrap_or_default(),
            PackageLoadReason::Refused(self.report),
        )
    }
}

fn rebind_envelope(root: &Path, verified: &VerifiedPackage) -> Result<(), PackageLoadError> {
    let sums = read_rebound_bytes(root, SUM_FILE, MAXIMUM_ENVELOPE_BYTES)?;
    if sha256(&sums) != verified.digest() {
        return Err(PackageLoadError::new(SUM_FILE, PackageLoadReason::Changed));
    }
    match verified.revision() {
        Some(revision) => {
            let bytes = read_rebound_bytes(root, REVISION_FILE, MAXIMUM_ENVELOPE_BYTES)?;
            let digest = sha256(&bytes);
            if verified.file_digest(REVISION_FILE).as_deref() != Some(&digest)
                || bytes != format!("{revision}\n").as_bytes()
            {
                return Err(PackageLoadError::new(
                    REVISION_FILE,
                    PackageLoadReason::Changed,
                ));
            }
        }
        None if std::fs::symlink_metadata(root.join(REVISION_FILE)).is_ok() => {
            return Err(PackageLoadError::new(
                REVISION_FILE,
                PackageLoadReason::Changed,
            ));
        }
        None => {}
    }
    Ok(())
}

fn read_rebound_bytes(root: &Path, path: &str, limit: u64) -> Result<Vec<u8>, PackageLoadError> {
    let full = root.join(path);
    let read = |error| PackageLoadError::new(path, PackageLoadReason::Read(error));
    let before = std::fs::symlink_metadata(&full).map_err(read)?;
    if before.file_type().is_symlink() {
        return Err(PackageLoadError::new(path, PackageLoadReason::Symlink));
    }
    if !before.is_file() {
        return Err(PackageLoadError::new(path, PackageLoadReason::Unexpected));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&full)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
        .map_err(read)?;
    if bytes.len() as u64 > limit {
        return Err(PackageLoadError::new(
            path,
            PackageLoadReason::FileTooLarge(limit),
        ));
    }
    let after = std::fs::symlink_metadata(&full).map_err(read)?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || !after.is_file()
        || after.file_type().is_symlink()
    {
        return Err(PackageLoadError::new(path, PackageLoadReason::Changed));
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut rendered = String::with_capacity(7 + digest.len() * 2);
    rendered.push_str("sha256:");
    for byte in digest {
        rendered.push(HEX[usize::from(byte >> 4)] as char);
        rendered.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    rendered
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EntryKind {
    File,
    Directory,
}

/// One template version read from disk: its sources, its decoded
/// `template.yaml`, and that file's path under the root.
type ReadTemplate = (TemplateSource, Document, String);

struct PackageReader<'a> {
    root: &'a Path,
    verified: Option<&'a VerifiedPackage>,
    files: Vec<PackageFile>,
    inputs: BTreeMap<String, Vec<u8>>,
    bytes: u64,
    entries: usize,
    found: Found,
}

impl PackageReader<'_> {
    /// The path a diagnostic names for `path` under the root.
    fn label(&self, path: &str) -> String {
        self.root.join(path).display().to_string()
    }

    /// Decode one authored YAML file, refusing every `${...}` expression in
    /// it. A refusal is noted, and the file yields nothing.
    fn decode<T>(
        &mut self,
        path: &str,
        bytes: &[u8],
        decode: impl FnOnce(Reader<'_>, &[u8]) -> Result<Decoded<T>, Report>,
    ) -> Option<Decoded<T>> {
        let mut hook = AuthoredExpressions;
        let reader = Reader::new(self.label(path)).with_hook(&mut hook);
        match decode(reader, bytes) {
            Ok(decoded) => Some(decoded),
            Err(report) => {
                self.found.note(path, report);
                None
            }
        }
    }

    /// Every template version under `templates/` whose files read, and the
    /// reference of every version directory, read or not.
    fn read_templates(
        &mut self,
    ) -> Result<(Vec<ReadTemplate>, BTreeSet<TemplateReference>), PackageLoadError> {
        let mut shipped = BTreeSet::new();
        let directory = self.root.join(TEMPLATES_DIRECTORY);
        let metadata = match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Vec::new(), shipped))
            }
            Err(error) => {
                return Err(PackageLoadError::new(
                    TEMPLATES_DIRECTORY,
                    PackageLoadReason::Read(error),
                ))
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(PackageLoadError::new(
                TEMPLATES_DIRECTORY,
                PackageLoadReason::Symlink,
            ));
        }
        if !metadata.is_dir() {
            return Err(PackageLoadError::new(
                TEMPLATES_DIRECTORY,
                PackageLoadReason::Unexpected,
            ));
        }
        let mut sources = Vec::new();
        for (id, kind) in self.list(TEMPLATES_DIRECTORY)? {
            let template = format!("{TEMPLATES_DIRECTORY}/{id}");
            expect_directory(&template, kind)?;
            for (version, kind) in self.list(&template)? {
                let directory = format!("{template}/{version}");
                expect_directory(&directory, kind)?;
                if let Some(source) = self.read_version(&id, &version, &directory)? {
                    sources.push(source);
                }
                shipped.insert(TemplateReference {
                    id: id.clone(),
                    version,
                });
            }
        }
        Ok((sources, shipped))
    }

    /// Read one template version directory. A file that reads but is
    /// refused is noted, and the version yields nothing.
    fn read_version(
        &mut self,
        id: &str,
        version: &str,
        directory: &str,
    ) -> Result<Option<ReadTemplate>, PackageLoadError> {
        let mut document = None;
        let mut schema = None;
        let mut sample = None;
        let mut refused = false;
        let mut locales = std::collections::BTreeMap::new();
        for (name, kind) in self.list(directory)? {
            let path = format!("{directory}/{name}");
            match (name.as_str(), kind) {
                (TEMPLATE_FILE, EntryKind::File) => {
                    document = Some(
                        self.read_document(
                            &path,
                            MESSAGING_TEMPLATE_KIND,
                            MAXIMUM_YAML_FILE_BYTES,
                        )?
                        .and_then(|bytes| self.decode(&path, &bytes, TemplateDocument::decode)),
                    );
                }
                (SCHEMA_FILE, EntryKind::File) => {
                    schema = Some(self.read_json(&path, FindingReason::SchemaSyntax)?);
                }
                (SAMPLE_FILE, EntryKind::File) => {
                    let read = self.read_json(&path, FindingReason::SampleSyntax)?;
                    refused |= read.is_none();
                    sample = read;
                }
                (_, EntryKind::Directory) => {
                    let sources = self.read_locale(&path)?;
                    locales.insert(name, sources);
                }
                (_, EntryKind::File) => {
                    return Err(PackageLoadError::new(&path, PackageLoadReason::Unexpected));
                }
            }
        }
        let missing = |file: &str| {
            PackageLoadError::new(
                &format!("{directory}/{file}"),
                PackageLoadReason::Read(std::io::ErrorKind::NotFound.into()),
            )
        };
        let document = document.ok_or_else(|| missing(TEMPLATE_FILE))?;
        let schema = schema.ok_or_else(|| missing(SCHEMA_FILE))?;
        let (Some(Decoded { value, document }), Some(schema), false) = (document, schema, refused)
        else {
            return Ok(None);
        };
        let source = TemplateSource {
            id: id.to_owned(),
            version: version.to_owned(),
            document: value,
            schema,
            locales,
            sample,
        };
        Ok(Some((
            source,
            document,
            format!("{directory}/{TEMPLATE_FILE}"),
        )))
    }

    fn read_locale(&mut self, directory: &str) -> Result<LocaleSources, PackageLoadError> {
        let mut sources = LocaleSources::default();
        for (name, kind) in self.list(directory)? {
            let path = format!("{directory}/{name}");
            let part = [PartKind::Subject, PartKind::Text, PartKind::Html]
                .into_iter()
                .find(|part| part.file_name() == name);
            let (Some(part), EntryKind::File) = (part, kind) else {
                return Err(PackageLoadError::new(&path, PackageLoadReason::Unexpected));
            };
            let text = self.read_file(&path, MAXIMUM_TEMPLATE_FILE_BYTES)?;
            match part {
                PartKind::Subject => sources.subject = Some(text),
                PartKind::Text => sources.text = Some(text),
                PartKind::Html => sources.html = Some(text),
            }
        }
        Ok(sources)
    }

    fn read_providers(
        &mut self,
        declared: &BTreeSet<String>,
    ) -> Result<BTreeMap<String, HttpProviderSource>, PackageLoadError> {
        let missing = |id: &str| {
            PackageLoadError::new(
                &format!("{PROVIDERS_DIRECTORY}/{id}/{PROVIDER_FILE}"),
                PackageLoadReason::Read(std::io::ErrorKind::NotFound.into()),
            )
        };
        let directory = self.root.join(PROVIDERS_DIRECTORY);
        let metadata = match std::fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return match declared.first() {
                    Some(id) => Err(missing(id)),
                    None => Ok(BTreeMap::new()),
                };
            }
            Err(error) => {
                return Err(PackageLoadError::new(
                    PROVIDERS_DIRECTORY,
                    PackageLoadReason::Read(error),
                ))
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(PackageLoadError::new(
                PROVIDERS_DIRECTORY,
                PackageLoadReason::Symlink,
            ));
        }
        if !metadata.is_dir() {
            return Err(PackageLoadError::new(
                PROVIDERS_DIRECTORY,
                PackageLoadReason::Unexpected,
            ));
        }
        let mut listed = BTreeSet::new();
        for (name, kind) in self.list(PROVIDERS_DIRECTORY)? {
            let path = format!("{PROVIDERS_DIRECTORY}/{name}");
            if kind != EntryKind::Directory || !declared.contains(&name) {
                return Err(PackageLoadError::new(&path, PackageLoadReason::Unexpected));
            }
            listed.insert(name);
        }
        let mut providers = BTreeMap::new();
        for id in declared {
            if !listed.contains(id) {
                return Err(missing(id));
            }
            if let Some(source) = self.read_provider(id)? {
                providers.insert(id.clone(), source);
            }
        }
        Ok(providers)
    }

    /// Read one provider directory. A `provider.yaml` that reads but is
    /// refused, or a script that does not compile, is noted, and the
    /// provider yields nothing.
    fn read_provider(&mut self, id: &str) -> Result<Option<HttpProviderSource>, PackageLoadError> {
        let directory = format!("{PROVIDERS_DIRECTORY}/{id}");
        let manifest_path = format!("{directory}/{PROVIDER_FILE}");
        let Some(bytes) = self.read_document(
            &manifest_path,
            MESSAGING_PROVIDER_KIND,
            MAXIMUM_YAML_FILE_BYTES,
        )?
        else {
            return Ok(None);
        };
        let Some(Decoded { value, document }) =
            self.decode(&manifest_path, &bytes, HttpProviderPackage::decode)
        else {
            return Ok(None);
        };
        let scripts: Vec<(&'static str, String)> = [
            ("prepareScript", Some(&value.prepare_script)),
            ("interpretScript", value.interpret_script.as_ref()),
            ("receiptScript", value.receipt_script.as_ref()),
        ]
        .into_iter()
        .filter_map(|(field, path)| path.map(|path| (field, path.clone())))
        .collect();
        // A link is refused where the manifest names it, never by reading
        // through it, and the message repeats no path.
        for (field, path) in &scripts {
            let linked = std::fs::symlink_metadata(self.root.join(format!("{directory}/{path}")))
                .is_ok_and(|metadata| metadata.file_type().is_symlink());
            if linked {
                let diagnostic = document.diagnostic_at_value(
                    Severity::Error,
                    "config.refused",
                    &format!("/{field}"),
                    "the script is a symbolic link, which a package may not contain",
                    "Replace the link with the script file itself, inside the provider directory.",
                );
                self.found
                    .note(&manifest_path, Report::new(vec![diagnostic]));
                return Ok(None);
            }
        }
        let mut expected: BTreeSet<String> = scripts.iter().map(|(_, path)| path.clone()).collect();
        expected.insert(PROVIDER_FILE.to_owned());
        self.expect_only(&directory, "", &expected)?;
        let mut sources = BTreeMap::new();
        for (field, path) in &scripts {
            let text = self.read_file(
                &format!("{directory}/{path}"),
                MAXIMUM_SCRIPT_SOURCE_BYTES as u64,
            )?;
            sources.insert(*field, text);
        }
        let source = HttpProviderSource {
            prepare: sources.remove("prepareScript").unwrap_or_default(),
            interpret: sources.remove("interpretScript"),
            receipt: sources.remove("receiptScript"),
            package: value,
        };
        let mut findings = source.package.findings();
        findings.extend(script_findings(&source.package, source.scripts()));
        self.found
            .note_findings(&manifest_path, &document, &findings);
        let refused = findings.iter().any(MessagingFinding::is_error);
        Ok((!refused).then_some(source))
    }

    /// Walk `directory` and refuse every entry that is not one of the
    /// `expected` files, relative to the provider directory, or a directory
    /// on the way to one.
    fn expect_only(
        &mut self,
        provider: &str,
        relative: &str,
        expected: &BTreeSet<String>,
    ) -> Result<(), PackageLoadError> {
        let directory = if relative.is_empty() {
            provider.to_owned()
        } else {
            format!("{provider}/{relative}")
        };
        for (name, kind) in self.list(&directory)? {
            let entry = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            let allowed = match kind {
                EntryKind::File => expected.contains(&entry),
                EntryKind::Directory => {
                    let prefix = format!("{entry}/");
                    expected.iter().any(|path| path.starts_with(&prefix))
                }
            };
            if !allowed {
                return Err(PackageLoadError::new(
                    &format!("{provider}/{entry}"),
                    PackageLoadReason::Unexpected,
                ));
            }
            if kind == EntryKind::Directory {
                self.expect_only(provider, &entry, expected)?;
            }
        }
        Ok(())
    }

    /// Read one JSON file beside a template. JSON is not an authored YAML
    /// format: a file that is not JSON, or that repeats an object key at any
    /// depth, is noted as `syntax`, at the line where it stops parsing, and
    /// yields nothing.
    fn read_json(
        &mut self,
        path: &str,
        syntax: FindingReason,
    ) -> Result<Option<Value>, PackageLoadError> {
        let text = self.read_file(path, MAXIMUM_TEMPLATE_FILE_BYTES)?;
        match serde_json::from_str::<StrictJson>(&text) {
            Ok(StrictJson(value)) => Ok(Some(value)),
            Err(error) => {
                let mut diagnostic = MessagingFinding::new(syntax, "").to_unplaced_diagnostic();
                diagnostic.source = Some(Source {
                    file: self.label(path),
                    line: Some(error.line()),
                    column: None,
                });
                self.found.note(path, Report::new(vec![diagnostic]));
                Ok(None)
            }
        }
    }

    /// List one directory under the root, sorted by name. Every entry counts
    /// against the package's entry bound before it is examined, and a
    /// hidden entry, a name that is not UTF-8, or a symbolic link is refused.
    fn list(&mut self, directory: &str) -> Result<Vec<(String, EntryKind)>, PackageLoadError> {
        let read = |error| PackageLoadError::new(directory, PackageLoadReason::Read(error));
        let mut listed = Vec::new();
        for entry in std::fs::read_dir(self.root.join(directory)).map_err(read)? {
            let entry = entry.map_err(read)?;
            self.entries += 1;
            if self.entries > MAXIMUM_PACKAGE_ENTRIES {
                return Err(PackageLoadError::new("", PackageLoadReason::TooManyEntries));
            }
            let Ok(name) = entry.file_name().into_string() else {
                return Err(PackageLoadError::new(
                    directory,
                    PackageLoadReason::Unexpected,
                ));
            };
            let path = format!("{directory}/{name}");
            if name.starts_with('.') {
                return Err(PackageLoadError::new(&path, PackageLoadReason::Unexpected));
            }
            let file_type = entry
                .file_type()
                .map_err(|error| PackageLoadError::new(&path, PackageLoadReason::Read(error)))?;
            let kind = if file_type.is_symlink() {
                return Err(PackageLoadError::new(&path, PackageLoadReason::Symlink));
            } else if file_type.is_dir() {
                EntryKind::Directory
            } else if file_type.is_file() {
                EntryKind::File
            } else {
                return Err(PackageLoadError::new(&path, PackageLoadReason::Unexpected));
            };
            listed.push((name, kind));
        }
        listed.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(listed)
    }

    /// Read one authored YAML file of at most `limit` bytes for the shared
    /// reader, which refuses one that is not UTF-8 at its first invalid byte.
    /// A file over `limit`, a bound no larger than the shared one, is refused
    /// here, for the format `kind` names, as the shared reader refuses a
    /// document over its own bound, and yields nothing.
    fn read_document(
        &mut self,
        path: &str,
        kind: &str,
        limit: u64,
    ) -> Result<Option<Vec<u8>>, PackageLoadError> {
        match self.read_bytes(path, limit) {
            Err(error) if matches!(error.reason, PackageLoadReason::FileTooLarge(_)) => {
                let mut diagnostic = Diagnostic::error(
                    "yaml.too-large",
                    "",
                    format!("the document is larger than the {limit}-byte bound of this file"),
                    "Split the content into smaller files, or move large embedded content into \
                     its own file.",
                );
                diagnostic.artifact = Some(kind.to_owned());
                diagnostic.source = Some(Source {
                    file: self.label(path),
                    line: None,
                    column: None,
                });
                self.found.note(path, Report::new(vec![diagnostic]));
                Ok(None)
            }
            read => read.map(Some),
        }
    }

    /// Read one regular file of at most `limit` bytes as UTF-8 and record it
    /// for the digest.
    fn read_file(&mut self, path: &str, limit: u64) -> Result<String, PackageLoadError> {
        let bytes = self.read_bytes(path, limit)?;
        String::from_utf8(bytes)
            .map_err(|_| PackageLoadError::new(path, PackageLoadReason::NotUtf8))
    }

    /// Read one regular file of at most `limit` bytes and record it for the
    /// digest.
    fn read_bytes(&mut self, path: &str, limit: u64) -> Result<Vec<u8>, PackageLoadError> {
        let full = self.root.join(path);
        let read = |error| PackageLoadError::new(path, PackageLoadReason::Read(error));
        let metadata = std::fs::symlink_metadata(&full).map_err(read)?;
        if metadata.file_type().is_symlink() {
            return Err(PackageLoadError::new(path, PackageLoadReason::Symlink));
        }
        if !metadata.is_file() {
            return Err(PackageLoadError::new(path, PackageLoadReason::Unexpected));
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&full)
            .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
            .map_err(read)?;
        let length = bytes.len() as u64;
        if length > limit {
            return Err(PackageLoadError::new(
                path,
                PackageLoadReason::FileTooLarge(limit),
            ));
        }
        self.bytes += length;
        if self.bytes > MAXIMUM_PACKAGE_BYTES {
            return Err(PackageLoadError::new("", PackageLoadReason::TooLarge));
        }
        let digest = sha256(&bytes);
        if self
            .verified
            .is_some_and(|verified| verified.file_digest(path).as_deref() != Some(&digest))
        {
            return Err(PackageLoadError::new(path, PackageLoadReason::Changed));
        }
        self.files.push(PackageFile {
            path: path.to_owned(),
            sha256: digest,
            bytes: length,
        });
        self.inputs.insert(path.to_owned(), bytes.clone());
        Ok(bytes)
    }
}

fn expect_directory(path: &str, kind: EntryKind) -> Result<(), PackageLoadError> {
    if kind == EntryKind::Directory {
        Ok(())
    } else {
        Err(PackageLoadError::new(path, PackageLoadReason::Unexpected))
    }
}

/// A JSON value read with every object key required to be unique, so a
/// reviewer and the runtime see the same constraint.
struct StrictJson(Value);

impl<'de> serde::Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = Value;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
                Ok(v.into())
            }

            fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
                Ok(v.into())
            }

            fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
                Ok(serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number))
            }

            fn visit_str<E>(self, v: &str) -> Result<Value, E> {
                Ok(Value::String(v.to_owned()))
            }

            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }

            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(StrictJson(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Value::Array(items))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Value, A::Error> {
                let mut object = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let StrictJson(value) = map.next_value()?;
                    if object.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("repeated object key"));
                    }
                }
                Ok(Value::Object(object))
            }
        }
        deserializer.deserialize_any(Visit).map(StrictJson)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The committed starter package, which every runtime test serves.
    pub(crate) fn starter_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/messaging/examples/starter")
    }

    /// Copy the starter package's content into `to`.
    pub(crate) fn copy_starter(to: &Path) {
        copy_tree(&starter_root(), to, true);
    }

    fn copy_tree(from: &Path, to: &Path, top: bool) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            if top
                && name != PACKAGE_FILE
                && name != TEMPLATES_DIRECTORY
                && name != PROVIDERS_DIRECTORY
            {
                continue;
            }
            let target = to.join(&name);
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target, false);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    fn starter_copy() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        copy_starter(root.path());
        root
    }

    fn refusal(root: &Path) -> PackageLoadError {
        load_project(root).unwrap_err()
    }

    /// The codes a refused package's report holds, with each one's file
    /// relative to `root` and its JSON Pointer.
    fn refused_codes(root: &Path) -> Vec<(String, String, String)> {
        let error = refusal(root);
        let report = error.report().unwrap_or_else(|| panic!("{error}"));
        let prefix = format!("{}/", root.display());
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                let file = diagnostic.source.as_ref().map_or(String::new(), |source| {
                    source.file.trim_start_matches(&prefix).to_owned()
                });
                (diagnostic.code.clone(), file, diagnostic.path.clone())
            })
            .collect()
    }

    const REMINDER: &str = "templates/appointment-reminder/1";
    const GATEWAY: &str = "providers/sms-gateway";

    #[test]
    fn the_starter_package_loads_with_a_digest_over_its_sorted_files() {
        let root = starter_copy();
        let loaded = load_project(root.path()).unwrap();
        let paths: Vec<&str> = loaded.files.iter().map(|file| file.path.as_str()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted);
        assert_eq!(paths.first(), Some(&PACKAGE_FILE));
        assert!(paths.contains(&"templates/appointment-reminder/1/fr/html.j2"));
        let inputs = package_inputs(root.path()).unwrap();
        assert_eq!(
            loaded.package.digest(),
            plan_package_inputs(root.path(), &inputs, None).unwrap()
        );
        assert!(registry_messaging_core::valid_package_digest(
            loaded.package.digest()
        ));
        assert_eq!(loaded.package.templates().count(), 2);
        let manifest = &loaded.files[0];
        let bytes = std::fs::read(root.path().join(PACKAGE_FILE)).unwrap();
        assert_eq!(manifest.bytes, bytes.len() as u64);
        assert_eq!(manifest.sha256, sha256(&bytes));
    }

    #[test]
    fn the_digest_is_reproducible_and_covers_exactly_the_package_files() {
        let root = starter_copy();
        let digest = load_project(root.path())
            .unwrap()
            .package
            .digest()
            .to_owned();
        let again = starter_copy();
        assert_eq!(load_project(again.path()).unwrap().package.digest(), digest);

        std::fs::write(root.path().join("README.md"), "notes").unwrap();
        std::fs::write(root.path().join("runtime.yaml"), "kind: x").unwrap();
        assert_eq!(load_project(root.path()).unwrap().package.digest(), digest);

        let text = root.path().join(REMINDER).join("en/text.j2");
        let original = std::fs::read_to_string(&text).unwrap();
        std::fs::write(&text, format!("{original} ")).unwrap();
        assert_ne!(load_project(root.path()).unwrap().package.digest(), digest);
        std::fs::write(&text, original).unwrap();
        assert_eq!(load_project(root.path()).unwrap().package.digest(), digest);
    }

    #[test]
    fn an_installed_package_verifies_and_rebinds_its_envelope_and_product_files() {
        let project = starter_copy();
        let inputs = package_inputs(project.path()).unwrap();
        let installed = tempfile::tempdir().unwrap();
        let root = installed.path().join("package");
        write_package_inputs(&root, &inputs, Some("test-revision")).unwrap();
        let verified = verify_package(&root, &package_limits(), PACKAGE_COMMAND).unwrap();
        let loaded = load_contents(&root, Some(&verified)).unwrap();
        assert_eq!(loaded.package.digest(), verified.digest());

        std::fs::write(root.join(SUM_FILE), b"changed\n").unwrap();
        let error = rebind_envelope(&root, &verified).unwrap_err();
        assert_eq!(error.path(), "package.root/SHA256SUMS");
        assert!(matches!(error.reason(), PackageLoadReason::Changed));

        write_package_inputs(
            &installed.path().join("second"),
            &inputs,
            Some("test-revision"),
        )
        .unwrap();
        let second = installed.path().join("second");
        let verified = verify_package(&second, &package_limits(), PACKAGE_COMMAND).unwrap();
        std::fs::write(second.join(REVISION_FILE), b"other-revision\n").unwrap();
        let error = rebind_envelope(&second, &verified).unwrap_err();
        assert_eq!(error.path(), "package.root/REVISION");
        assert!(matches!(error.reason(), PackageLoadReason::Changed));

        write_package_inputs(&installed.path().join("third"), &inputs, None).unwrap();
        let third = installed.path().join("third");
        let verified = verify_package(&third, &package_limits(), PACKAGE_COMMAND).unwrap();
        std::fs::write(third.join(REMINDER).join("en/text.j2"), b"swapped").unwrap();
        let error = load_contents(&third, Some(&verified)).unwrap_err();
        assert_eq!(
            error.path(),
            "package.root/templates/appointment-reminder/1/en/text.j2"
        );
        assert!(matches!(error.reason(), PackageLoadReason::Changed));
    }

    #[test]
    fn authored_project_environment_expressions_are_refused_in_structured_yaml() {
        for (path, from, to) in [
            (PACKAGE_FILE, "role: sender", "role: ${ROLE}"),
            (
                "providers/sms-gateway/provider.yaml",
                "prepareScript: scripts/prepare.rhai",
                "prepareScript: ${SCRIPT}",
            ),
            (
                "templates/appointment-reminder/1/template.yaml",
                "channel: email",
                "channel: ${CHANNEL}",
            ),
        ] {
            let project = starter_copy();
            let file = project.path().join(path);
            let text = std::fs::read_to_string(&file).unwrap().replace(from, to);
            std::fs::write(file, text).unwrap();
            let error = load_project(project.path()).unwrap_err();
            assert_eq!(error.path(), format!("package.root/{path}"));
            let codes = refused_codes(project.path());
            assert_eq!(codes.len(), 1, "{codes:?}");
            assert_eq!(codes[0].0, "config.substitution-not-allowed");
            assert_eq!(codes[0].1, path);
        }
    }

    #[test]
    fn a_package_without_templates_needs_no_templates_directory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(PACKAGE_FILE),
            concat!(
                "apiVersion: id.registrystack.org/formats/messaging/project/v1alpha1\n",
                "kind: MessagingProject\n",
                "project: {id: operations, version: \"1\"}\n",
                "accessProfiles:\n",
                "  - {id: operations, principalClaim: sub, requesterClients: [console],\n",
                "     requiredScopes: unrestricted, role: operator,\n",
                "     requestsPerMinute: 60, burst: 10}\n",
            ),
        )
        .unwrap();
        let loaded = load_project(root.path()).unwrap();
        assert_eq!(loaded.files.len(), 1);
        assert_eq!(loaded.package.templates().count(), 0);
    }

    #[test]
    fn a_missing_manifest_is_a_read_failure() {
        let root = tempfile::tempdir().unwrap();
        let error = refusal(root.path());
        assert!(error.is_read_failure(), "{error}");
        assert_eq!(error.path(), "package.root/messaging.yaml");
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_anywhere_in_the_package_is_refused() {
        let root = starter_copy();
        let text = root.path().join(REMINDER).join("en/text.j2");
        let outside = root.path().join("outside.j2");
        std::fs::rename(&text, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &text).unwrap();
        let error = refusal(root.path());
        assert!(
            matches!(error.reason(), PackageLoadReason::Symlink),
            "{error}"
        );
        assert_eq!(error.path(), format!("package.root/{REMINDER}/en/text.j2"));

        let root = starter_copy();
        let manifest = root.path().join(PACKAGE_FILE);
        std::fs::rename(&manifest, root.path().join("real.yaml")).unwrap();
        std::os::unix::fs::symlink(root.path().join("real.yaml"), &manifest).unwrap();
        let error = refusal(root.path());
        assert!(
            matches!(error.reason(), PackageLoadReason::Symlink),
            "{error}"
        );
    }

    #[test]
    fn an_entry_outside_the_layout_is_refused_by_path() {
        for (entry, directory) in [
            (format!("{REMINDER}/notes.txt"), false),
            (format!("{REMINDER}/en/footer.j2"), false),
            (format!("{REMINDER}/en/.DS_Store"), false),
            ("templates/.cache".to_owned(), true),
            ("templates/stray.yaml".to_owned(), false),
            ("templates/appointment-reminder/1.txt".to_owned(), false),
            (format!("{REMINDER}/en/partials"), true),
        ] {
            let root = starter_copy();
            let path = root.path().join(&entry);
            if directory {
                std::fs::create_dir(&path).unwrap();
            } else {
                std::fs::write(&path, "x").unwrap();
            }
            let error = refusal(root.path());
            assert!(
                matches!(error.reason(), PackageLoadReason::Unexpected),
                "{entry}: {error}"
            );
            assert_eq!(error.path(), format!("package.root/{entry}"));
        }
    }

    #[test]
    fn oversized_and_non_utf8_files_are_refused() {
        let root = starter_copy();
        let text = root.path().join(REMINDER).join("en/text.j2");
        std::fs::write(
            &text,
            "a".repeat(usize::try_from(MAXIMUM_TEMPLATE_FILE_BYTES).unwrap() + 1),
        )
        .unwrap();
        assert!(matches!(
            refusal(root.path()).reason(),
            PackageLoadReason::FileTooLarge(MAXIMUM_TEMPLATE_FILE_BYTES)
        ));

        std::fs::write(&text, [0xff, 0xfe]).unwrap();
        let error = refusal(root.path());
        assert!(
            matches!(error.reason(), PackageLoadReason::NotUtf8),
            "{error}"
        );
        assert_eq!(error.path(), format!("package.root/{REMINDER}/en/text.j2"));
    }

    /// A template or provider file of exactly the shared document bound,
    /// padded with comment lines, is read (CFG-YAML-6): the package adds no
    /// lower bound of its own for either YAML file.
    #[test]
    fn a_yaml_file_of_exactly_the_document_bound_is_read() {
        let root = starter_copy();
        for file in [
            format!("{REMINDER}/{TEMPLATE_FILE}"),
            format!("{GATEWAY}/{PROVIDER_FILE}"),
        ] {
            let path = root.path().join(&file);
            let mut bytes = std::fs::read(&path).unwrap();
            let padding = MAXIMUM_DOCUMENT_BYTES - bytes.len();
            bytes.extend(std::iter::repeat_n(b'#', padding - 1));
            bytes.push(b'\n');
            assert_eq!(bytes.len(), MAXIMUM_DOCUMENT_BYTES);
            std::fs::write(&path, bytes).unwrap();
        }
        load_project(root.path()).unwrap();
    }

    /// The code, the file relative to `root`, and whether a line is named,
    /// of every diagnostic a refused load reports.
    fn located(root: &Path) -> Vec<(String, String, bool)> {
        let error = refusal(root);
        let report = error.report().unwrap_or_else(|| panic!("{error}"));
        let prefix = format!("{}/", root.display());
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                let source = diagnostic.source.as_ref().unwrap();
                (
                    diagnostic.code.clone(),
                    source.file.trim_start_matches(&prefix).to_owned(),
                    source.line.is_some(),
                )
            })
            .collect()
    }

    #[test]
    fn an_oversized_or_non_utf8_yaml_file_is_refused_by_the_shared_reader_at_its_file() {
        let root = starter_copy();
        let template = format!("{REMINDER}/{TEMPLATE_FILE}");
        let provider = format!("{GATEWAY}/{PROVIDER_FILE}");
        std::fs::write(
            root.path().join(&template),
            "#".repeat(MAXIMUM_DOCUMENT_BYTES + 1),
        )
        .unwrap();
        let mut bytes = std::fs::read(root.path().join(&provider)).unwrap();
        bytes.extend_from_slice(b"# a comment \xff\n");
        std::fs::write(root.path().join(&provider), bytes).unwrap();
        assert_eq!(
            located(root.path()),
            [
                ("yaml.too-large".to_owned(), template, false),
                ("yaml.not-utf8".to_owned(), provider, true),
            ]
        );
        let error = refusal(root.path());
        let too_large = &error.report().unwrap().diagnostics()[0];
        assert!(too_large
            .message
            .contains(&MAXIMUM_DOCUMENT_BYTES.to_string()));
        assert_eq!(too_large.artifact.as_deref(), Some(MESSAGING_TEMPLATE_KIND));

        let root = starter_copy();
        std::fs::write(
            root.path().join(PACKAGE_FILE),
            "#".repeat(usize::try_from(MAXIMUM_MANIFEST_BYTES).unwrap() + 1),
        )
        .unwrap();
        assert_eq!(
            located(root.path()),
            [("yaml.too-large".to_owned(), PACKAGE_FILE.to_owned(), false)]
        );
    }

    #[test]
    fn the_entry_bound_is_enforced_before_the_layout_is_judged() {
        let root = starter_copy();
        let locale = root.path().join(REMINDER).join("en");
        for index in 0..MAXIMUM_PACKAGE_ENTRIES {
            std::fs::write(locale.join(format!("extra-{index}")), "").unwrap();
        }
        assert!(matches!(
            refusal(root.path()).reason(),
            PackageLoadReason::TooManyEntries
        ));
    }

    #[test]
    fn an_unknown_key_in_a_template_descriptor_is_refused_with_its_path() {
        let root = starter_copy();
        let file = root.path().join(REMINDER).join(TEMPLATE_FILE);
        let original = std::fs::read_to_string(&file).unwrap();
        std::fs::write(&file, format!("{original}fallback: en\n")).unwrap();
        let error = refusal(root.path());
        assert_eq!(
            error.path(),
            format!("package.root/{REMINDER}/{TEMPLATE_FILE}")
        );
        assert_eq!(
            refused_codes(root.path()),
            [(
                "config.unknown-key".to_owned(),
                format!("{REMINDER}/{TEMPLATE_FILE}"),
                "/fallback".to_owned()
            )]
        );
    }

    #[test]
    fn a_template_refusal_names_its_version_directory() {
        let root = starter_copy();
        std::fs::write(
            root.path().join(REMINDER).join("en/text.j2"),
            "Hello {{ name ",
        )
        .unwrap();
        let error = refusal(root.path());
        assert_eq!(error.path(), format!("package.root/{REMINDER}/en/text.j2"));
        assert_eq!(
            refused_codes(root.path()),
            [(
                "messaging.template.part-syntax".to_owned(),
                format!("{REMINDER}/en/text.j2"),
                String::new()
            )]
        );

        let root = starter_copy();
        std::fs::remove_file(root.path().join(REMINDER).join(SCHEMA_FILE)).unwrap();
        let error = refusal(root.path());
        assert_eq!(
            error.path(),
            format!("package.root/{REMINDER}/{SCHEMA_FILE}")
        );

        let root = starter_copy();
        std::fs::write(
            root.path().join(REMINDER).join(SCHEMA_FILE),
            "{\n  \"type\": ",
        )
        .unwrap();
        assert_eq!(
            refused_codes(root.path()),
            [(
                "messaging.template.schema-syntax".to_owned(),
                format!("{REMINDER}/{SCHEMA_FILE}"),
                String::new()
            )]
        );
        let error = refusal(root.path());
        let line = error.report().unwrap().diagnostics()[0]
            .source
            .as_ref()
            .and_then(|source| source.line);
        assert_eq!(line, Some(2));
    }

    /// A repeated object key in `schema.json` or `sample.json` is refused at
    /// its line, instead of the last value winning over the one a reviewer
    /// read first, at any depth.
    #[test]
    fn a_repeated_key_in_a_template_json_file_is_refused() {
        for (file, syntax, text) in [
            (
                SCHEMA_FILE,
                "messaging.template.schema-syntax",
                "{\n  \"type\": \"object\",\n  \"properties\": {\"name\": {\"type\": \"string\", \"maxLength\": 10,\n    \"maxLength\": 100000}}\n}",
            ),
            (
                SAMPLE_FILE,
                "messaging.template.sample-syntax",
                "{\"name\": \"a\",\n \"name\": \"b\"}",
            ),
        ] {
            let root = starter_copy();
            std::fs::write(root.path().join(REMINDER).join(file), text).unwrap();
            assert_eq!(
                refused_codes(root.path()),
                [(syntax.to_owned(), format!("{REMINDER}/{file}"), String::new())],
                "{file}"
            );
            let error = refusal(root.path());
            let line = error.report().unwrap().diagnostics()[0]
                .source
                .as_ref()
                .and_then(|source| source.line);
            assert!(line.is_some_and(|line| line >= 2), "{file}: {line:?}");
        }
    }

    #[test]
    fn a_declared_version_the_package_does_not_ship_is_refused() {
        let root = starter_copy();
        std::fs::remove_dir_all(root.path().join("templates/appointment-reminder-sms")).unwrap();
        let error = refusal(root.path());
        assert_eq!(error.path(), "package.root/messaging.yaml");
        let codes = refused_codes(root.path());
        assert_eq!(codes.len(), 1, "{codes:?}");
        assert_eq!(codes[0].0, "messaging.project.missing-template");
        assert_eq!(codes[0].1, PACKAGE_FILE);
        assert!(codes[0].2.starts_with("/templates/"), "{codes:?}");

        let root = starter_copy();
        let shipped = root.path().join(REMINDER);
        std::fs::rename(
            &shipped,
            root.path().join("templates/appointment-reminder/2"),
        )
        .unwrap();
        let codes = refused_codes(root.path());
        assert_eq!(
            codes
                .iter()
                .map(|(code, file, _)| (code.as_str(), file.as_str()))
                .collect::<Vec<_>>(),
            [
                (
                    "messaging.template.undeclared",
                    "templates/appointment-reminder/2/template.yaml"
                ),
                ("messaging.project.missing-template", PACKAGE_FILE),
            ]
        );
    }

    #[test]
    fn the_starter_package_ships_its_http_provider_digested() {
        let root = starter_copy();
        let loaded = load_project(root.path()).unwrap();
        let paths: Vec<&str> = loaded.files.iter().map(|file| file.path.as_str()).collect();
        for file in [
            "providers/sms-gateway/provider.yaml",
            "providers/sms-gateway/scripts/prepare.rhai",
            "providers/sms-gateway/scripts/interpret.rhai",
            "providers/sms-gateway/scripts/receipt.rhai",
        ] {
            assert!(paths.contains(&file), "{file} is not digested");
        }
        assert_eq!(
            loaded.providers.keys().collect::<Vec<_>>(),
            vec!["sms-gateway"]
        );
        let gateway = &loaded.providers["sms-gateway"];
        assert_eq!(gateway.package.prepare_script, "scripts/prepare.rhai");
        let scripts = gateway.scripts();
        assert!(scripts.prepare.contains("fn prepare"));
        assert!(scripts.interpret.is_some());
        assert!(scripts.receipt.is_some());
        // The SMTP relay records no receipts; the gateway declares callbacks.
        assert_eq!(
            loaded.receipt_providers(),
            BTreeSet::from(["sms-gateway".to_owned()])
        );

        let digest = loaded.package.digest().to_owned();
        let script = root.path().join(GATEWAY).join("scripts/prepare.rhai");
        let original = std::fs::read_to_string(&script).unwrap();
        std::fs::write(&script, format!("{original}\n")).unwrap();
        assert_ne!(load_project(root.path()).unwrap().package.digest(), digest);
    }

    #[test]
    fn the_starter_provider_is_the_mock_example_byte_for_byte() {
        let mock = starter_root().join("../providers/mock");
        let starter = starter_root().join(GATEWAY);
        for file in [
            "provider.yaml",
            "scripts/prepare.rhai",
            "scripts/interpret.rhai",
            "scripts/receipt.rhai",
        ] {
            assert_eq!(
                std::fs::read(mock.join(file)).unwrap(),
                std::fs::read(starter.join(file)).unwrap(),
                "{file} differs from the mock example"
            );
        }
    }

    #[test]
    fn a_declared_http_provider_without_its_directory_is_refused() {
        let root = starter_copy();
        std::fs::remove_dir_all(root.path().join(GATEWAY)).unwrap();
        let error = refusal(root.path());
        assert!(error.is_read_failure(), "{error}");
        assert_eq!(
            error.path(),
            format!("package.root/{GATEWAY}/provider.yaml")
        );

        let root = starter_copy();
        std::fs::remove_dir_all(root.path().join(PROVIDERS_DIRECTORY)).unwrap();
        let error = refusal(root.path());
        assert_eq!(
            error.path(),
            format!("package.root/{GATEWAY}/provider.yaml")
        );

        let root = starter_copy();
        std::fs::remove_file(root.path().join(GATEWAY).join("scripts/receipt.rhai")).unwrap();
        let error = refusal(root.path());
        assert!(error.is_read_failure(), "{error}");
        assert_eq!(
            error.path(),
            format!("package.root/{GATEWAY}/scripts/receipt.rhai")
        );
    }

    #[test]
    fn a_provider_entry_outside_the_layout_is_refused_by_path() {
        for (entry, directory) in [
            ("providers/mail-relay".to_owned(), true),
            ("providers/unknown".to_owned(), true),
            ("providers/stray.yaml".to_owned(), false),
            (format!("{GATEWAY}/README.md"), false),
            (format!("{GATEWAY}/connection.example.yaml"), false),
            (format!("{GATEWAY}/.hidden"), false),
            (format!("{GATEWAY}/fixtures"), true),
            (format!("{GATEWAY}/scripts/extra.rhai"), false),
        ] {
            let root = starter_copy();
            let path = root.path().join(&entry);
            if directory {
                std::fs::create_dir(&path).unwrap();
            } else {
                std::fs::write(&path, "x").unwrap();
            }
            let error = refusal(root.path());
            assert!(
                matches!(error.reason(), PackageLoadReason::Unexpected),
                "{entry}: {error}"
            );
            assert_eq!(error.path(), format!("package.root/{entry}"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_under_providers_is_refused() {
        let root = starter_copy();
        let script = root.path().join(GATEWAY).join("scripts/prepare.rhai");
        let outside = root.path().join("outside.rhai");
        std::fs::rename(&script, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &script).unwrap();
        let error = refusal(root.path());
        let report = error.report().unwrap_or_else(|| panic!("{error}"));
        let [diagnostic] = report.diagnostics() else {
            panic!("{error}");
        };
        assert_eq!(diagnostic.code, "config.refused");
        assert_eq!(diagnostic.path, "/prepareScript");
        let source = diagnostic.source.as_ref().expect("a position");
        assert!(source.file.ends_with(&format!("{GATEWAY}/provider.yaml")));
        assert!(source.line.is_some() && source.column.is_some());
        assert!(!diagnostic.message.contains("outside.rhai"));

        let root = starter_copy();
        let directory = root.path().join(GATEWAY);
        let outside = root.path().join("outside");
        std::fs::rename(&directory, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &directory).unwrap();
        let error = refusal(root.path());
        assert!(
            matches!(error.reason(), PackageLoadReason::Symlink),
            "{error}"
        );
        assert_eq!(error.path(), format!("package.root/{GATEWAY}"));
    }

    #[test]
    fn a_provider_that_does_not_parse_check_or_compile_is_refused_at_its_file() {
        let root = starter_copy();
        let manifest = root.path().join(GATEWAY).join("provider.yaml");
        let original = std::fs::read_to_string(&manifest).unwrap();
        std::fs::write(
            &manifest,
            format!("{original}endpoint: https://x.example/\n"),
        )
        .unwrap();
        let error = refusal(root.path());
        assert_eq!(
            error.path(),
            format!("package.root/{GATEWAY}/provider.yaml")
        );
        assert_eq!(
            refused_codes(root.path()),
            [(
                "config.unknown-key".to_owned(),
                format!("{GATEWAY}/provider.yaml"),
                "/endpoint".to_owned()
            )]
        );

        let root = starter_copy();
        assert!(original.contains("maximumConcurrentRequests: 8"));
        std::fs::write(
            root.path().join(GATEWAY).join("provider.yaml"),
            original.replace(
                "maximumConcurrentRequests: 8",
                "maximumConcurrentRequests: 0",
            ),
        )
        .unwrap();
        assert_eq!(
            refused_codes(root.path()),
            [(
                "config.out-of-range".to_owned(),
                format!("{GATEWAY}/provider.yaml"),
                "/capabilities/maximumConcurrentRequests".to_owned()
            )]
        );

        let root = starter_copy();
        std::fs::write(
            root.path().join(GATEWAY).join("provider.yaml"),
            original.replace("maximumConcurrentRequests", "concurrencyLimit"),
        )
        .unwrap();
        assert_eq!(
            refused_codes(root.path()),
            [
                (
                    "config.missing-key".to_owned(),
                    format!("{GATEWAY}/provider.yaml"),
                    "/capabilities".to_owned()
                ),
                (
                    "config.removed-key".to_owned(),
                    format!("{GATEWAY}/provider.yaml"),
                    "/capabilities/concurrencyLimit".to_owned()
                )
            ]
        );

        let root = starter_copy();
        std::fs::write(
            root.path().join(GATEWAY).join("scripts/interpret.rhai"),
            "fn interpret(response) {",
        )
        .unwrap();
        let error = refusal(root.path());
        assert_eq!(
            error.path(),
            format!("package.root/{GATEWAY}/scripts/interpret.rhai")
        );
        assert_eq!(
            refused_codes(root.path()),
            [(
                "messaging.provider.script-does-not-compile".to_owned(),
                format!("{GATEWAY}/scripts/interpret.rhai"),
                String::new()
            )]
        );
    }
}
