//! Bundle loading and package binding. An authored bundle is a directory with
//! one `manifest.yaml` plus the templates, labels, schemas, fonts, and
//! vendored Typst packages it governs. A deployment package adds the shared
//! `SHA256SUMS` envelope. Runtime loads bind the exact captured bytes back to
//! that verified envelope before parsing or rendering any product content.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use registry_platform_yaml::{Diagnostic, Document, Report, Source};
use serde_json::Value;
use typst::foundations::Bytes;

use crate::hash::sha256_hex;
use crate::labels::{labels_path, read_labels};
use crate::manifest::{
    error_at, read_manifest, refused, DocumentSpec, Manifest, ReadManifest, MANIFEST_FILE,
};
use crate::problem::{ProblemKind, RenderProblem};

/// Asset policy defaults; a runtime may not raise the request total above
/// this without a reviewed change.
pub const DEFAULT_MAX_ASSET_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_ASSET_BYTES: usize = 8 * 1024 * 1024;

/// A document type with its governed content loaded and verified.
#[derive(Debug, Clone)]
pub struct LoadedDocument {
    pub spec: DocumentSpec,
    /// Locale name -> parsed label table.
    pub labels: BTreeMap<String, Value>,
    /// The raw schema JSON, when the document declares one.
    pub schema: Option<Value>,
}

/// A loaded authored bundle or verified deployment package.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Retained only to redact any host path a future diagnostic might
    /// expose. Rendering never reopens this directory.
    pub root: PathBuf,
    pub manifest: Manifest,
    /// Exact bytes of the loaded `manifest.yaml`.
    pub manifest_bytes: Vec<u8>,
    /// Hex SHA-256 identity. For a deployment package this is the shared
    /// package digest without its `sha256:` label; raw authoring loads use the
    /// manifest digest only for preview output.
    pub bundle_hash: String,
    pub documents: BTreeMap<String, LoadedDocument>,
    /// Locale name -> the label table as the shared reader accepted it, so a
    /// later check places its findings at the line and column they concern.
    pub(crate) label_sources: BTreeMap<String, Document>,
    /// The binary's baseline set (`typst-assets` order) first, then bundle
    /// fonts sorted by path — the same book order the Typst CLI builds, so
    /// library and CLI renders agree byte for byte.
    pub fonts: Vec<typst::text::Font>,
    /// Immutable bytes read once and, for a deployment package, bound to the
    /// shared package envelope before any consumer parses or renders them.
    pub(crate) snapshot: BundleSnapshot,
    /// The warnings the manifest and label tables were accepted with, for
    /// `registry-render check` to report.
    pub(crate) warnings: Vec<Diagnostic>,
}

/// The name diagnostics give the bundle file at `relative`: the bundle
/// directory as it was given, joined with the path inside it (CFG-DIAG-1).
pub(crate) fn bundle_file_name(root: &Path, relative: &str) -> String {
    root.join(relative).display().to_string()
}

/// Read the captured manifest bytes, naming the file under `root`.
fn parse_manifest(root: &Path, bytes: &[u8]) -> Result<ReadManifest, RenderProblem> {
    let file = bundle_file_name(root, MANIFEST_FILE);
    read_manifest(&file, bytes)
        .map_err(|report| refused(ProblemKind::ManifestInvalid, &file, report))
}

/// One immutable view of every governed bundle file. The shared `Bytes`
/// values make cloning a bundle or constructing a per-render world cheap
/// without reopening any path.
#[derive(Debug, Clone, Default)]
pub(crate) struct BundleSnapshot {
    files: Arc<BTreeMap<String, Bytes>>,
}

impl BundleSnapshot {
    fn load(root: &Path) -> Result<(Self, ReadManifest, Vec<u8>), RenderProblem> {
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        {
            use std::ffi::OsStr;

            let directory = open_bundle_root(root)?;
            let manifest_bytes = read_bundle_file(
                &directory,
                OsStr::new(MANIFEST_FILE),
                &root.join(MANIFEST_FILE),
            )?;
            let manifest = parse_manifest(root, &manifest_bytes)?;

            let mut files = BTreeMap::new();
            files.insert(MANIFEST_FILE.to_owned(), Bytes::new(manifest_bytes.clone()));
            capture_bundle_directory(&directory, Path::new(""), root, &mut files)?;
            Ok((
                Self {
                    files: Arc::new(files),
                },
                manifest,
                manifest_bytes,
            ))
        }

        #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
        {
            Err(RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!(
                    "cannot securely snapshot bundle {} on this platform",
                    root.display()
                ),
            ))
        }
    }

    /// Capture a package without interpreting product bytes. The caller
    /// binds this snapshot to shared verification before parsing the
    /// manifest or constructing any other product consumer.
    fn load_unparsed(root: &Path) -> Result<(Self, Vec<u8>), RenderProblem> {
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        {
            use std::ffi::OsStr;

            let directory = open_bundle_root(root)?;
            let manifest_bytes = read_bundle_file(
                &directory,
                OsStr::new(MANIFEST_FILE),
                &root.join(MANIFEST_FILE),
            )?;
            let mut files = BTreeMap::new();
            files.insert(MANIFEST_FILE.to_owned(), Bytes::new(manifest_bytes.clone()));
            capture_bundle_directory(&directory, Path::new(""), root, &mut files)?;
            Ok((
                Self {
                    files: Arc::new(files),
                },
                manifest_bytes,
            ))
        }

        #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
        {
            Err(RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!(
                    "cannot securely snapshot bundle {} on this platform",
                    root.display()
                ),
            ))
        }
    }

    pub(crate) fn get(&self, path: &str) -> Option<Bytes> {
        self.files.get(path).cloned()
    }

    pub(crate) fn is_dir(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        self.files.keys().any(|key| key.starts_with(&prefix))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&String, &Bytes)> {
        self.files.iter()
    }

    fn product_files(&self) -> Self {
        let files = self
            .files
            .iter()
            .filter(|(path, _)| !registry_platform_config::package::is_envelope_file(path))
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect();
        Self {
            files: Arc::new(files),
        }
    }

    fn package_inputs(&self) -> BTreeMap<String, Vec<u8>> {
        self.files
            .iter()
            .map(|(path, bytes)| (path.clone(), bytes.to_vec()))
            .collect()
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
const SNAPSHOT_DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
    .union(rustix::fs::OFlags::DIRECTORY)
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::CLOEXEC);

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
const SNAPSHOT_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::NONBLOCK)
    .union(rustix::fs::OFlags::CLOEXEC);

/// Open each spelling component relative to the descriptor for its parent.
/// `O_NOFOLLOW` only protects the final component of a single `open`, so an
/// absolute call for the complete root would still follow ancestor symlinks
/// and a trailing slash could make the kernel follow a symlink at the root.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn open_bundle_root(root: &Path) -> Result<std::fs::File, RenderProblem> {
    use std::ffi::OsStr;

    use rustix::fs::{open, openat, Mode};

    if root.as_os_str().is_empty() {
        return Err(RenderProblem::new(
            ProblemKind::ManifestInvalid,
            "bundle directory path must not be empty",
        ));
    }

    let anchor = if root.is_absolute() { "/" } else { "." };
    let descriptor = open(anchor, SNAPSHOT_DIRECTORY_FLAGS, Mode::empty()).map_err(|err| {
        RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!("cannot open bundle path anchor {anchor}: {err}"),
        )
    })?;
    let mut directory = std::fs::File::from(descriptor);

    for component in root.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => OsStr::new(".."),
            Component::Normal(name) => name,
            Component::Prefix(_) => {
                return Err(RenderProblem::new(
                    ProblemKind::ManifestInvalid,
                    format!("bundle directory path is unsupported: {}", root.display()),
                ));
            }
        };
        let descriptor = openat(&directory, name, SNAPSHOT_DIRECTORY_FLAGS, Mode::empty())
            .map_err(|err| {
                RenderProblem::new(
                    ProblemKind::ManifestInvalid,
                    format!(
                        "cannot open bundle directory {} without following links: {err}",
                        root.display()
                    ),
                )
            })?;
        directory = std::fs::File::from(descriptor);
    }

    Ok(directory)
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn read_bundle_file(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
    display: &Path,
) -> Result<Vec<u8>, RenderProblem> {
    use std::io::Read as _;

    use rustix::fs::{openat, Mode};

    let descriptor =
        openat(directory, name, SNAPSHOT_FILE_FLAGS, Mode::empty()).map_err(|err| {
            RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!(
                    "bundle entry cannot be opened without following links: {}: {err}",
                    display.display()
                ),
            )
        })?;
    let mut file = std::fs::File::from(descriptor);
    let metadata = file.metadata().map_err(|err| {
        RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!("cannot inspect bundle entry {}: {err}", display.display()),
        )
    })?;
    if !metadata.is_file() {
        return Err(RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!("bundle entry is not a regular file: {}", display.display()),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|err| {
        RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!("cannot read bundle entry {}: {err}", display.display()),
        )
    })?;
    Ok(bytes)
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn capture_bundle_directory(
    directory: &std::fs::File,
    relative: &Path,
    root: &Path,
    files: &mut BTreeMap<String, Bytes>,
) -> Result<(), RenderProblem> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    use rustix::fs::{openat, Dir, Mode};

    let entries = Dir::read_from(directory).map_err(|err| {
        RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!(
                "cannot read bundle directory {}: {err}",
                root.join(relative).display()
            ),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!(
                    "cannot read bundle directory {}: {err}",
                    root.join(relative).display()
                ),
            )
        })?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let os_name = OsStr::from_bytes(name.to_bytes());
        let Some(utf8_name) = os_name.to_str() else {
            return Err(RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!(
                    "bundle path under {} is not valid UTF-8",
                    root.join(relative).display()
                ),
            ));
        };
        if relative.as_os_str().is_empty() && os_name == OsStr::new(MANIFEST_FILE) {
            // The root manifest was deliberately read and parsed first. Keep
            // those exact bytes instead of reopening the path during capture.
            continue;
        }
        let child_relative = relative.join(utf8_name);
        let display = root.join(&child_relative);

        match openat(directory, name, SNAPSHOT_DIRECTORY_FLAGS, Mode::empty()) {
            Ok(descriptor) => {
                let child = std::fs::File::from(descriptor);
                capture_bundle_directory(&child, &child_relative, root, files)?;
            }
            Err(_) => {
                let bytes = read_bundle_file(directory, os_name, &display)?;
                let key = relative_path_key(&child_relative)?;
                if files.insert(key.clone(), Bytes::new(bytes)).is_some() {
                    return Err(RenderProblem::new(
                        ProblemKind::ManifestInvalid,
                        format!("bundle paths collide after normalization: {key}"),
                    ));
                }
            }
        }
    }
    Ok(())
}

impl Bundle {
    /// Load raw authoring source. Deployment envelope files are refused so an
    /// already-built package cannot silently become the source of another.
    pub fn load(root: &Path) -> Result<Self, RenderProblem> {
        let (snapshot, manifest, manifest_bytes) = BundleSnapshot::load(root)?;
        if let Some(path) = snapshot
            .iter()
            .map(|(path, _)| path.as_str())
            .find(|path| registry_platform_config::package::is_envelope_file(path))
        {
            return Err(RenderProblem::new(
                ProblemKind::InvalidArgument,
                format!(
                    "authoring bundle contains package envelope file {path}; edit the source bundle and build a new directory with `registry-render package --bundle <source> --output <directory>`"
                ),
            ));
        }
        let bundle_hash = sha256_hex(&manifest_bytes);
        Self::assemble(root, manifest, manifest_bytes, snapshot, bundle_hash)
    }

    /// Load source for authoring commands, or verify and load a current
    /// package when the directory has the shared envelope. This lets an
    /// operator inspect or compile the exact package they will deploy while
    /// keeping `package` itself source-only and write-once.
    pub fn load_for_preview(root: &Path) -> Result<Self, RenderProblem> {
        match std::fs::symlink_metadata(root.join(registry_platform_config::package::SUM_FILE)) {
            Ok(_) => {
                let verified = registry_platform_config::package::verify_package(
                    root,
                    &crate::runtime::package_limits(),
                    "registry-render package",
                )
                .map_err(crate::runtime::package_problem)?;
                Self::load_package(root, &verified)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::load(root),
            Err(error) => Err(RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!(
                    "cannot inspect package envelope {}: {error}",
                    root.join(registry_platform_config::package::SUM_FILE)
                        .display()
                ),
            )),
        }
    }

    /// Capture a package once, prove those consumed bytes are the bytes the
    /// shared verifier accepted, and assemble only product-owned content.
    pub fn load_package(
        root: &Path,
        verified: &registry_platform_config::package::VerifiedPackage,
    ) -> Result<Self, RenderProblem> {
        let (snapshot, manifest_bytes) = BundleSnapshot::load_unparsed(root)?;
        bind_verified_snapshot(&snapshot, verified)?;
        let manifest = parse_manifest(root, &manifest_bytes)?;
        let bundle_hash = verified
            .digest()
            .strip_prefix("sha256:")
            .expect("the shared verifier returns a sha256 label")
            .to_owned();
        Self::assemble(
            root,
            manifest,
            manifest_bytes,
            snapshot.product_files(),
            bundle_hash,
        )
    }

    /// Exact authored files supplied to the shared package writer.
    pub(crate) fn package_inputs(&self) -> BTreeMap<String, Vec<u8>> {
        self.snapshot.package_inputs()
    }

    /// Assemble the documents from the captured bytes, reporting every
    /// missing or refused file at once.
    fn assemble(
        root: &Path,
        read: ReadManifest,
        manifest_bytes: Vec<u8>,
        snapshot: BundleSnapshot,
        bundle_hash: String,
    ) -> Result<Self, RenderProblem> {
        let ReadManifest {
            manifest,
            document: manifest_document,
        } = read;
        let mut findings = Findings::default();
        findings.manifest.extend(manifest_document.warnings());
        let mut tables: BTreeMap<String, Option<Value>> = BTreeMap::new();
        let mut label_documents = BTreeMap::new();
        let mut documents = BTreeMap::new();
        for (index, spec) in manifest.documents.iter().enumerate() {
            let mut labels = BTreeMap::new();
            for (position, locale) in spec.labels.iter().enumerate() {
                let rel = labels_path(locale);
                let table = tables.entry(locale.clone()).or_insert_with(|| {
                    let bytes = snapshot.get(&rel)?;
                    match read_labels(&bundle_file_name(root, &rel), bytes.as_slice()) {
                        Ok(read) => {
                            findings.labels.extend(read.document.warnings());
                            label_documents.insert(locale.clone(), read.document);
                            Some(read.table)
                        }
                        Err(report) => {
                            findings.labels.extend(report);
                            None
                        }
                    }
                });
                match table {
                    Some(table) => {
                        labels.insert(locale.clone(), table.clone());
                    }
                    None if snapshot.get(&rel).is_none() => {
                        findings.manifest.push(error_at(
                            &manifest_document,
                            "render.bundle.missing-labels",
                            &format!("/documents/{index}/labels/{position}"),
                            &format!("the bundle has no label table {rel}"),
                            &format!("Write {rel} with the RenderLabels envelope, or remove the locale from the document."),
                        ));
                    }
                    None => {}
                }
            }
            let schema = match &spec.schema {
                None => None,
                Some(rel) => {
                    let pointer = format!("/documents/{index}/schemaFile");
                    match bundle_key(rel)
                        .and_then(|key| snapshot.get(&key).map(|bytes| (key, bytes)))
                    {
                        None => {
                            findings.manifest.push(error_at(
                                &manifest_document,
                                "render.bundle.missing-schema-file",
                                &pointer,
                                "the schema file is not in the bundle",
                                "Add the schema file at this path inside the bundle, or correct the path.",
                            ));
                            None
                        }
                        Some((key, bytes)) => {
                            match serde_json::from_slice::<Value>(bytes.as_slice()) {
                                Ok(value) => Some(value),
                                Err(error) => {
                                    findings.manifest.push(invalid_schema(root, &key, &error));
                                    None
                                }
                            }
                        }
                    }
                }
            };
            // The entry bytes must be in the same snapshot the world will
            // consume; failing here gives a plain problem instead of a
            // compile one.
            if bundle_key(&spec.entry).is_none_or(|key| snapshot.get(&key).is_none()) {
                findings.manifest.push(error_at(
                    &manifest_document,
                    "render.bundle.missing-entry-file",
                    &format!("/documents/{index}/entryFile"),
                    "the entry file is not in the bundle",
                    "Add the .typ file at this path inside the bundle, or correct the path.",
                ));
            }
            documents.insert(
                spec.id.clone(),
                LoadedDocument {
                    spec: spec.clone(),
                    labels,
                    schema,
                },
            );
        }
        let fonts = load_fonts(root, &snapshot, &mut findings.fonts);
        let warnings = findings.into_result(root)?;
        Ok(Self {
            root: root.canonicalize().unwrap_or_else(|_| root.to_path_buf()),
            manifest,
            manifest_bytes,
            bundle_hash,
            documents,
            label_sources: label_documents,
            fonts,
            snapshot,
            warnings,
        })
    }

    pub fn document(&self, id: &str) -> Result<&LoadedDocument, RenderProblem> {
        self.documents.get(id).ok_or_else(|| {
            RenderProblem::new(
                ProblemKind::UnknownDocument,
                format!(
                    "bundle has no document type {id:?}; available: {}",
                    self.documents
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        })
    }
}

fn bind_verified_snapshot(
    snapshot: &BundleSnapshot,
    verified: &registry_platform_config::package::VerifiedPackage,
) -> Result<(), RenderProblem> {
    let sums = snapshot.get(registry_platform_config::package::SUM_FILE);
    let captured_digest = sums
        .as_ref()
        .map(|bytes| registry_platform_config::sha256_uri(bytes.as_slice()));
    if captured_digest.as_deref() != Some(verified.digest()) {
        return Err(RenderProblem::new(
            ProblemKind::BundleTampered,
            "SHA256SUMS changed after package verification; rebuild the package with `registry-render package` and deploy the whole directory",
        )
        .with_locations(vec![registry_platform_config::package::SUM_FILE.to_owned()]));
    }

    let captured_files = snapshot
        .iter()
        .map(|(path, _)| path.as_str())
        .filter(|path| *path != registry_platform_config::package::SUM_FILE)
        .collect::<std::collections::BTreeSet<_>>();
    let verified_files = verified.files().collect::<std::collections::BTreeSet<_>>();
    let mut mismatches = captured_files
        .symmetric_difference(&verified_files)
        .map(|path| (*path).to_owned())
        .collect::<Vec<_>>();
    for path in verified.files() {
        let Some(bytes) = snapshot.get(path) else {
            continue;
        };
        let captured = registry_platform_config::sha256_uri(bytes.as_slice());
        if verified.file_digest(path).as_deref() != Some(captured.as_str()) {
            mismatches.push(path.to_owned());
        }
    }
    mismatches.sort();
    mismatches.dedup();
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(RenderProblem::new(
            ProblemKind::BundleTampered,
            format!(
                "package content changed after verification: {}; rebuild the package with `registry-render package` and deploy the whole directory",
                mismatches.join(", ")
            ),
        )
        .with_locations(mismatches))
    }
}

/// What assembling a bundle found, by the problem kind it maps to.
#[derive(Default)]
struct Findings {
    manifest: Report,
    labels: Report,
    fonts: Report,
}

impl Findings {
    /// The warnings when nothing was refused; otherwise one problem
    /// carrying every finding, named by the first kind that has an error:
    /// the manifest, then the label tables, then the fonts.
    fn into_result(self, root: &Path) -> Result<Vec<Diagnostic>, RenderProblem> {
        let kind = if self.manifest.has_errors() {
            Some(ProblemKind::ManifestInvalid)
        } else if self.labels.has_errors() {
            Some(ProblemKind::LabelsInvalid)
        } else if self.fonts.has_errors() {
            Some(ProblemKind::FontInvalid)
        } else {
            None
        };
        let mut diagnostics = self.manifest.into_diagnostics();
        diagnostics.extend(self.labels.into_diagnostics());
        diagnostics.extend(self.fonts.into_diagnostics());
        match kind {
            None => Ok(diagnostics),
            Some(kind) => Err(RenderProblem::new(
                kind,
                format!("the bundle {} was refused", root.display()),
            )
            .with_diagnostics(diagnostics)),
        }
    }
}

/// The snapshot key of a manifest path, or none when it leaves the bundle.
fn bundle_key(path: &Path) -> Option<String> {
    relative_path_key(path).ok()
}

/// A schema file that is not JSON, placed where the JSON parser stopped.
fn invalid_schema(root: &Path, key: &str, error: &serde_json::Error) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(
        "render.bundle.invalid-schema",
        "",
        "the schema file is not valid JSON",
        "Correct the JSON at this position; the file holds one JSON Schema (draft 2020-12).",
    );
    diagnostic.source = Some(Source {
        file: bundle_file_name(root, key),
        line: Some(error.line()),
        column: Some(error.column()),
    });
    diagnostic
}

/// The binary's baseline set (`typst-assets` order) first, then bundle
/// fonts sorted by relative path — the same book order the Typst CLI
/// builds. The order is part of byte stability: it decides font fallback,
/// so it may never depend on filesystem iteration order.
fn load_fonts(
    root: &Path,
    snapshot: &BundleSnapshot,
    findings: &mut Report,
) -> Vec<typst::text::Font> {
    let mut fonts = Vec::new();
    let mut files = Vec::new();
    for (path, bytes) in snapshot.iter() {
        let Some(name) = path.strip_prefix("fonts/") else {
            continue;
        };
        // Match the prior direct `fonts/` directory contract. License texts
        // commonly live beside the fonts they govern (the examples ship
        // OFL.txt), and nested files are governed but not font inputs.
        let is_font_file = !name.contains('/')
            && Path::new(name)
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| {
                    matches!(
                        e.to_ascii_lowercase().as_str(),
                        "ttf" | "otf" | "ttc" | "woff" | "woff2"
                    )
                });
        if is_font_file {
            files.push((path, bytes));
        }
    }
    // Baseline set first, then bundle fonts, both in deterministic order.
    // The order mirrors the Typst CLI's book (embedded assets before
    // --font-path entries) so library and CLI renders agree byte for byte,
    // and it decides fallback: it may never depend on filesystem order.
    for raw in typst_assets::fonts() {
        let data = typst::foundations::Bytes::new(raw.to_vec());
        if let Some(font) = typst::text::Font::new(data, 0) {
            fonts.push(font);
        }
    }
    for (path, bytes) in files {
        let data = bytes.clone();
        let mut loaded_any = false;
        for font in typst::text::Font::iter(data) {
            fonts.push(font);
            loaded_any = true;
        }
        if !loaded_any {
            let mut diagnostic = Diagnostic::error(
                "render.font.invalid",
                "",
                "the file is not a loadable font",
                "Replace it with a TrueType, OpenType, or WOFF font, or move it out of fonts/.",
            );
            diagnostic.source = Some(Source {
                file: bundle_file_name(root, path),
                line: None,
                column: None,
            });
            findings.push(diagnostic);
        }
    }
    fonts
}

fn relative_path_key(path: &Path) -> Result<String, RenderProblem> {
    let slash_path = path.to_string_lossy().replace('\\', "/");
    let mut segments = Vec::new();
    for component in Path::new(&slash_path).components() {
        match component {
            Component::Normal(segment) => segments.push(segment.to_string_lossy()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(RenderProblem::new(
                    ProblemKind::ManifestInvalid,
                    format!("bundle path {} must stay inside the bundle", path.display()),
                ));
            }
        }
    }
    if segments.is_empty() {
        return Err(RenderProblem::new(
            ProblemKind::ManifestInvalid,
            "bundle path must not be empty",
        ));
    }
    Ok(segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABELS_CAPTURED: &str = "apiVersion: id.registrystack.org/formats/render/labels/v1alpha1\nkind: RenderLabels\nlabels:\n  title: Captured\n";

    fn findings(problem: &RenderProblem) -> Vec<(&str, &str, Option<usize>, Option<usize>)> {
        problem
            .diagnostics
            .iter()
            .map(|diagnostic| {
                let source = diagnostic
                    .source
                    .as_ref()
                    .expect("every finding names its file");
                (
                    diagnostic.code.as_str(),
                    diagnostic.path.as_str(),
                    source.line,
                    source.column,
                )
            })
            .collect()
    }

    #[test]
    fn cfg_diag_5_every_missing_or_refused_file_is_reported_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let root_path = dir.path().canonicalize().unwrap();
        let root = root_path.as_path();
        for sub in ["templates", "labels", "schemas", "fonts"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::write(
            root.join(MANIFEST_FILE),
            "apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: notice\n    version: 1\n    entryFile: templates/notice.typ\n    schemaFile: schemas/notice.schema.json\n    labels: [en, fr, sw]\n",
        )
        .unwrap();
        std::fs::write(root.join("labels/en.yaml"), LABELS_CAPTURED).unwrap();
        std::fs::write(root.join("labels/fr.yaml"), "title: Capturé\n").unwrap();
        std::fs::write(root.join("schemas/notice.schema.json"), "{\n  \"type\": \n").unwrap();
        std::fs::write(root.join("fonts/broken.ttf"), "not a font").unwrap();

        let problem = Bundle::load(root).expect_err("refused");
        assert_eq!(problem.kind, ProblemKind::ManifestInvalid);
        assert_eq!(
            findings(&problem),
            [
                (
                    "render.bundle.missing-labels",
                    "/documents/0/labels/2",
                    Some(9),
                    Some(22)
                ),
                ("render.bundle.invalid-schema", "", Some(3), Some(0)),
                (
                    "render.bundle.missing-entry-file",
                    "/documents/0/entryFile",
                    Some(7),
                    Some(16)
                ),
                ("config.missing-envelope", "", Some(1), Some(1)),
                ("render.font.invalid", "", None, None),
            ]
        );
        let files: Vec<String> = problem
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.source.as_ref().unwrap().file.clone())
            .collect();
        assert_eq!(files[0], root.join(MANIFEST_FILE).display().to_string());
        assert_eq!(
            files[1],
            root.join("schemas/notice.schema.json")
                .display()
                .to_string()
        );
        assert_eq!(files[3], root.join("labels/fr.yaml").display().to_string());
        assert_eq!(
            files[4],
            root.join("fonts/broken.ttf").display().to_string()
        );
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn bundle_root_and_ancestor_symlinks_are_refused_for_every_spelling() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();

        let direct_target = base.join("direct-target");
        std::fs::create_dir(&direct_target).unwrap();
        let direct_link = base.join("current");
        symlink(&direct_target, &direct_link).unwrap();
        let trailing_slash = PathBuf::from(format!("{}/", direct_link.display()));
        let error = BundleSnapshot::load(&trailing_slash).unwrap_err();
        assert_eq!(error.kind, ProblemKind::ManifestInvalid);

        let ancestor_target = base.join("ancestor-target");
        std::fs::create_dir_all(ancestor_target.join("bundle")).unwrap();
        let ancestor_link = base.join("deploy");
        symlink(&ancestor_target, &ancestor_link).unwrap();
        let ancestor_bundle = ancestor_link.join("bundle");
        let error = BundleSnapshot::load(&ancestor_bundle).unwrap_err();
        assert_eq!(error.kind, ProblemKind::ManifestInvalid);
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn source_load_checks_the_manifest_before_capturing_descendants() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root_path = dir.path().canonicalize().unwrap();
        let root = root_path.as_path();
        symlink(root, root.join("descendant-link")).unwrap();

        let missing = Bundle::load(root).unwrap_err();
        assert_eq!(missing.kind, ProblemKind::ManifestInvalid);
        assert!(missing.detail.contains(MANIFEST_FILE));

        std::fs::write(root.join(MANIFEST_FILE), "not: [valid").unwrap();
        let malformed = Bundle::load(root).unwrap_err();
        assert_eq!(malformed.kind, ProblemKind::ManifestInvalid);
        assert!(malformed.detail.contains("manifest.yaml was refused"));
        assert_eq!(malformed.diagnostics[0].code, "yaml.unexpected-end");

        std::fs::write(
            root.join(MANIFEST_FILE),
            "apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments: []\n",
        )
        .unwrap();
        let unsafe_entry = Bundle::load(root).unwrap_err();
        assert_eq!(unsafe_entry.kind, ProblemKind::ManifestInvalid);
        assert!(unsafe_entry.detail.contains("without following links"));
    }

    #[test]
    fn assembly_uses_captured_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let root_path = dir.path().canonicalize().unwrap();
        let root = root_path.as_path();
        for sub in ["templates", "labels", "schemas", "fonts"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        std::fs::write(
            root.join(MANIFEST_FILE),
            "apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: notice\n    version: 1\n    entryFile: templates/notice.typ\n    schemaFile: schemas/notice.schema.json\n    labels: [en]\n",
        )
        .unwrap();
        let entry = root.join("templates/notice.typ");
        let labels = root.join("labels/en.yaml");
        let schema = root.join("schemas/notice.schema.json");
        let font = root.join("fonts/NotoSans-Regular.ttf");
        std::fs::write(&entry, "Captured").unwrap();
        std::fs::write(&labels, LABELS_CAPTURED).unwrap();
        std::fs::write(&schema, r#"{"type":"object"}"#).unwrap();
        std::fs::write(
            &font,
            include_bytes!("../assets/starter-fonts/NotoSans-Regular.ttf"),
        )
        .unwrap();
        let (snapshot, manifest, manifest_bytes) = BundleSnapshot::load(root).unwrap();
        let expected_hash = sha256_hex(&manifest_bytes);

        // Every path used by assembly changes after capture. Assembly must
        // still parse and validate only the captured bytes.
        std::fs::write(root.join(MANIFEST_FILE), "not the captured manifest").unwrap();
        std::fs::remove_file(&entry).unwrap();
        std::fs::write(&labels, "not: [valid").unwrap();
        std::fs::write(&schema, "not json").unwrap();
        std::fs::write(&font, "not a font").unwrap();

        let bundle = Bundle::assemble(
            root,
            manifest,
            manifest_bytes,
            snapshot,
            expected_hash.clone(),
        )
        .unwrap();
        let document = bundle.document("notice").unwrap();
        assert_eq!(document.labels["en"]["title"], "Captured");
        assert_eq!(document.schema.as_ref().unwrap()["type"], "object");
        assert_eq!(bundle.bundle_hash, expected_hash);
        assert!(
            bundle.fonts.len() > typst_assets::fonts().count(),
            "the captured bundle font is loaded after the baseline set"
        );
    }

    #[test]
    fn accepted_manifest_path_spellings_render_from_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let root_path = dir.path().canonicalize().unwrap();
        let root = root_path.as_path();
        std::fs::create_dir_all(root.join("templates")).unwrap();
        std::fs::create_dir_all(root.join("schemas")).unwrap();
        std::fs::write(
            root.join(MANIFEST_FILE),
            "apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: notice\n    version: 1\n    entryFile: ./templates//notice.typ\n    schemaFile: schemas//./notice.schema.json\n",
        )
        .unwrap();
        std::fs::write(root.join("templates/notice.typ"), "= Notice").unwrap();
        std::fs::write(
            root.join("schemas/notice.schema.json"),
            r#"{"type":"object"}"#,
        )
        .unwrap();
        let bundle = Bundle::load(root).unwrap();
        let document = bundle.document("notice").unwrap();
        let request = crate::render::RenderRequest {
            locale: None,
            data: serde_json::json!({}),
            assets: BTreeMap::new(),
            issued_at: "2026-09-19T00:00:00Z".parse().unwrap(),
        };
        let rendered = crate::render::render(&bundle, document, &request, false).unwrap();

        assert_eq!(rendered.deps, vec!["templates/notice.typ"]);
        assert_eq!(document.schema.as_ref().unwrap()["type"], "object");
    }

    #[test]
    fn package_load_refuses_bytes_replaced_after_shared_verification() {
        let source = tempfile::tempdir().unwrap();
        std::fs::create_dir(source.path().join("templates")).unwrap();
        std::fs::write(
            source.path().join(MANIFEST_FILE),
            "apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: notice\n    version: 1\n    entryFile: templates/notice.typ\n",
        )
        .unwrap();
        std::fs::write(source.path().join("templates/notice.typ"), "= Accepted").unwrap();
        let source_root = source.path().canonicalize().unwrap();
        let authored = Bundle::load(&source_root).unwrap();

        let parent = tempfile::tempdir().unwrap();
        let package = parent.path().canonicalize().unwrap().join("package");
        registry_platform_config::package::write_package(
            &package,
            &authored.package_inputs(),
            None,
            &crate::runtime::package_limits(),
            "registry-render package",
        )
        .unwrap();
        let verified = registry_platform_config::package::verify_package(
            &package,
            &crate::runtime::package_limits(),
            "registry-render package",
        )
        .unwrap();
        std::fs::write(package.join("templates/notice.typ"), "= Replaced").unwrap();

        let problem = Bundle::load_package(&package, &verified)
            .expect_err("captured replacement must not be consumed");
        assert_eq!(problem.kind, ProblemKind::BundleTampered);
        assert!(problem.detail.contains("templates/notice.typ"));

        let manifest_package = parent
            .path()
            .canonicalize()
            .unwrap()
            .join("manifest-package");
        registry_platform_config::package::write_package(
            &manifest_package,
            &authored.package_inputs(),
            None,
            &crate::runtime::package_limits(),
            "registry-render package",
        )
        .unwrap();
        let verified = registry_platform_config::package::verify_package(
            &manifest_package,
            &crate::runtime::package_limits(),
            "registry-render package",
        )
        .unwrap();
        std::fs::write(manifest_package.join(MANIFEST_FILE), "not: [valid").unwrap();

        let problem = Bundle::load_package(&manifest_package, &verified)
            .expect_err("manifest replacement must be bound before it is parsed");
        assert_eq!(problem.kind, ProblemKind::BundleTampered);
        assert!(problem.detail.contains(MANIFEST_FILE));
    }
}
