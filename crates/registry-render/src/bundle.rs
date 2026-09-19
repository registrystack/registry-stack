//! Bundle loading, verification, and sealing. A bundle is a directory: one
//! `manifest.yaml` plus the templates, labels, schemas, fonts, and vendored
//! packages it governs. Sealing hashes every governed file; serving requires
//! a sealed bundle, compiling does not.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use typst::foundations::Bytes;

use crate::hash::sha256_hex;
use crate::manifest::{DocumentSpec, Manifest, MANIFEST_FILE};
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

/// A loaded bundle. `Bundle::load` accepts unsealed bundles (for compile and
/// authoring); `Bundle::load_sealed` is what `serve` uses.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Retained only to redact any host path a future diagnostic might
    /// expose. Rendering never reopens this directory.
    pub root: PathBuf,
    pub manifest: Manifest,
    /// Exact bytes of the loaded `manifest.yaml`.
    pub manifest_bytes: Vec<u8>,
    /// sha256 of the manifest bytes; identifies the sealed content set.
    pub bundle_hash: String,
    pub documents: BTreeMap<String, LoadedDocument>,
    /// The binary's baseline set (`typst-assets` order) first, then bundle
    /// fonts sorted by path — the same book order the Typst CLI builds, so
    /// library and CLI renders agree byte for byte.
    pub fonts: Vec<typst::text::Font>,
    /// Immutable bytes read once and, for a sealed bundle, verified against
    /// the manifest before any consumer parses or renders them.
    pub(crate) snapshot: BundleSnapshot,
}

/// One immutable view of every governed bundle file. The shared `Bytes`
/// values make cloning a bundle or constructing a per-render world cheap
/// without reopening any path.
#[derive(Debug, Clone, Default)]
pub(crate) struct BundleSnapshot {
    files: Arc<BTreeMap<String, Bytes>>,
}

impl BundleSnapshot {
    fn load(
        root: &Path,
        require_sealed: bool,
    ) -> Result<(Self, Manifest, Vec<u8>, std::fs::File), RenderProblem> {
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        {
            use std::ffi::OsStr;

            let directory = open_bundle_root(root)?;
            let manifest_bytes = read_bundle_file(
                &directory,
                OsStr::new(MANIFEST_FILE),
                &root.join(MANIFEST_FILE),
            )?;
            let manifest = Manifest::parse(&manifest_bytes)?;
            if require_sealed && !manifest.is_sealed() {
                return Err(RenderProblem::new(
                    ProblemKind::BundleUnsealed,
                    "serve requires a sealed bundle; run `registry-render seal` first",
                ));
            }

            let mut files = BTreeMap::new();
            files.insert(MANIFEST_FILE.to_owned(), Bytes::new(manifest_bytes.clone()));
            capture_bundle_directory(&directory, Path::new(""), root, &mut files)?;
            Ok((
                Self {
                    files: Arc::new(files),
                },
                manifest,
                manifest_bytes,
                directory,
            ))
        }

        #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
        {
            let _ = require_sealed;
            Err(RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!(
                    "cannot securely snapshot bundle {} on this platform",
                    root.display()
                ),
            ))
        }
    }

    fn hashes(&self) -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        for (path, bytes) in self.iter() {
            if path != MANIFEST_FILE {
                files.insert(path.clone(), sha256_hex(bytes.as_slice()));
            }
        }
        files
    }

    pub(crate) fn get(&self, path: &str) -> Option<Bytes> {
        self.files.get(path).cloned()
    }

    pub(crate) fn is_dir(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        self.files.keys().any(|key| key.starts_with(&prefix))
    }

    fn iter(&self) -> impl Iterator<Item = (&String, &Bytes)> {
        self.files.iter()
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
    /// Load a bundle without requiring it to be sealed. If it is sealed, the
    /// hashes are verified.
    pub fn load(root: &Path) -> Result<Self, RenderProblem> {
        let (snapshot, manifest, manifest_bytes, _directory) = BundleSnapshot::load(root, false)?;
        if manifest.is_sealed() {
            verify_hashes(&snapshot, &manifest)?;
        }
        Self::assemble(root, manifest, manifest_bytes, snapshot)
    }

    /// Load a bundle and require a verified seal.
    pub fn load_sealed(root: &Path) -> Result<Self, RenderProblem> {
        let (snapshot, manifest, manifest_bytes, _directory) = BundleSnapshot::load(root, true)?;
        verify_hashes(&snapshot, &manifest)?;
        Self::assemble(root, manifest, manifest_bytes, snapshot)
    }

    fn assemble(
        root: &Path,
        manifest: Manifest,
        manifest_bytes: Vec<u8>,
        snapshot: BundleSnapshot,
    ) -> Result<Self, RenderProblem> {
        let bundle_hash = sha256_hex(&manifest_bytes);
        let mut documents = BTreeMap::new();
        for spec in manifest.documents.clone() {
            let mut labels = BTreeMap::new();
            for locale in &spec.labels {
                let rel = format!("labels/{locale}.yaml");
                let bytes = snapshot.get(&rel).ok_or_else(|| {
                    RenderProblem::new(
                        ProblemKind::LabelsInvalid,
                        format!(
                            "document {:?} declares label {locale:?}, but {rel} is missing",
                            spec.id
                        ),
                    )
                    .with_locations(vec![rel.clone()])
                })?;
                let table: Value = serde_norway::from_slice(bytes.as_slice()).map_err(|err| {
                    RenderProblem::new(
                        ProblemKind::LabelsInvalid,
                        format!("label file labels/{locale}.yaml is not valid YAML: {err}"),
                    )
                })?;
                let table = require_string_map(&table, locale)?;
                labels.insert(locale.clone(), table);
            }
            let schema = match &spec.schema {
                None => None,
                Some(rel) => {
                    let key = relative_path_key(rel)?;
                    let bytes = snapshot.get(&key).ok_or_else(|| {
                        RenderProblem::new(
                            ProblemKind::ManifestInvalid,
                            format!("document {:?} schema {} is missing", spec.id, rel.display()),
                        )
                    })?;
                    let value: Value = serde_json::from_slice(bytes.as_slice()).map_err(|err| {
                        RenderProblem::new(
                            ProblemKind::ManifestInvalid,
                            format!("schema {} is not valid JSON: {err}", rel.display()),
                        )
                    })?;
                    Some(value)
                }
            };
            // The entry bytes must be in the same snapshot the world will
            // consume; failing here gives a plain problem instead of a
            // compile one.
            let entry_key = relative_path_key(&spec.entry)?;
            if snapshot.get(&entry_key).is_none() {
                return Err(RenderProblem::new(
                    ProblemKind::ManifestInvalid,
                    format!(
                        "document {:?} entry {} does not exist",
                        spec.id,
                        spec.entry.display()
                    ),
                ));
            }
            documents.insert(
                spec.id.clone(),
                LoadedDocument {
                    spec,
                    labels,
                    schema,
                },
            );
        }
        let fonts = load_fonts(&snapshot)?;
        Ok(Self {
            root: root.canonicalize().unwrap_or_else(|_| root.to_path_buf()),
            manifest,
            manifest_bytes,
            bundle_hash,
            documents,
            fonts,
            snapshot,
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

    /// Compute and write per-file hashes into the bundle's manifest, making
    /// it sealed. Returns the new manifest.
    pub fn seal(root: &Path) -> Result<Manifest, RenderProblem> {
        let (snapshot, mut manifest, _, directory) = BundleSnapshot::load(root, false)?;
        manifest.hashes = Some(snapshot.hashes());
        let serialized = serde_norway::to_string(&manifest).map_err(|err| {
            RenderProblem::new(
                ProblemKind::Internal,
                format!("cannot serialize manifest: {err}"),
            )
        })?;
        write_manifest(&directory, root, serialized.as_bytes())?;
        Ok(manifest)
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn write_manifest(
    directory: &std::fs::File,
    root: &Path,
    bytes: &[u8],
) -> Result<(), RenderProblem> {
    use std::io::Write as _;

    use rustix::fs::{openat, Mode, OFlags};

    let flags = OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let descriptor = openat(directory, MANIFEST_FILE, flags, Mode::empty()).map_err(|err| {
        RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!(
                "cannot open {} for writing: {err}",
                root.join(MANIFEST_FILE).display()
            ),
        )
    })?;
    let mut file = std::fs::File::from(descriptor);
    let metadata = file.metadata().map_err(|err| {
        RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!(
                "cannot inspect bundle entry {}: {err}",
                root.join(MANIFEST_FILE).display()
            ),
        )
    })?;
    if !metadata.is_file() {
        return Err(RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!(
                "bundle entry is not a regular file: {}",
                root.join(MANIFEST_FILE).display()
            ),
        ));
    }
    file.set_len(0)
        .and_then(|()| file.write_all(bytes))
        .map_err(|err| {
            RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!("cannot write {}: {err}", root.join(MANIFEST_FILE).display()),
            )
        })
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn write_manifest(
    _directory: &std::fs::File,
    root: &Path,
    _bytes: &[u8],
) -> Result<(), RenderProblem> {
    Err(RenderProblem::new(
        ProblemKind::ManifestInvalid,
        format!(
            "cannot securely seal bundle {} on this platform",
            root.display()
        ),
    ))
}

fn verify_hashes(snapshot: &BundleSnapshot, manifest: &Manifest) -> Result<(), RenderProblem> {
    let declared = manifest.hashes.as_ref().expect("caller checked is_sealed");
    let mut mismatches = Vec::new();
    for (rel, want) in declared {
        match snapshot.get(rel) {
            Some(bytes) if sha256_hex(bytes.as_slice()) == *want => {}
            Some(_) => mismatches.push(format!("{rel} (content changed)")),
            None => mismatches.push(format!("{rel} (missing)")),
        }
    }
    for (rel, _) in snapshot.iter() {
        if rel != MANIFEST_FILE && !declared.contains_key(rel) {
            mismatches.push(format!("{rel} (not covered by the manifest)"));
        }
    }
    if !mismatches.is_empty() {
        return Err(RenderProblem::new(
            ProblemKind::BundleTampered,
            format!(
                "sealed bundle does not match its manifest: {}",
                mismatches.join("; ")
            ),
        )
        .with_locations(mismatches));
    }
    Ok(())
}

fn require_string_map(table: &Value, locale: &str) -> Result<Value, RenderProblem> {
    let ok = table
        .as_object()
        .is_some_and(|map| map.values().all(|v| v.is_string()));
    if ok {
        Ok(table.clone())
    } else {
        Err(RenderProblem::new(
            ProblemKind::LabelsInvalid,
            format!(
                "label file labels/{locale}.yaml must be a flat map of string keys to string values"
            ),
        ))
    }
}

/// The binary's baseline set (`typst-assets` order) first, then bundle
/// fonts sorted by relative path — the same book order the Typst CLI
/// builds. The order is part of byte stability: it decides font fallback,
/// so it may never depend on filesystem iteration order.
fn load_fonts(snapshot: &BundleSnapshot) -> Result<Vec<typst::text::Font>, RenderProblem> {
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
            return Err(RenderProblem::new(
                ProblemKind::FontInvalid,
                format!(
                    "font {} is not a loadable font file",
                    Path::new(path)
                        .file_name()
                        .map(|n| n.to_string_lossy())
                        .unwrap_or_default()
                ),
            ));
        }
    }
    Ok(fonts)
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
        let error = BundleSnapshot::load(&trailing_slash, false).unwrap_err();
        assert_eq!(error.kind, ProblemKind::ManifestInvalid);
        let error = Bundle::seal(&trailing_slash).unwrap_err();
        assert_eq!(error.kind, ProblemKind::ManifestInvalid);

        let ancestor_target = base.join("ancestor-target");
        std::fs::create_dir_all(ancestor_target.join("bundle")).unwrap();
        let ancestor_link = base.join("deploy");
        symlink(&ancestor_target, &ancestor_link).unwrap();
        let ancestor_bundle = ancestor_link.join("bundle");
        let error = BundleSnapshot::load(&ancestor_bundle, false).unwrap_err();
        assert_eq!(error.kind, ProblemKind::ManifestInvalid);
        let error = Bundle::seal(&ancestor_bundle).unwrap_err();
        assert_eq!(error.kind, ProblemKind::ManifestInvalid);
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn sealed_load_checks_the_manifest_before_capturing_descendants() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root_path = dir.path().canonicalize().unwrap();
        let root = root_path.as_path();
        symlink(root, root.join("descendant-link")).unwrap();

        let missing = Bundle::load_sealed(root).unwrap_err();
        assert_eq!(missing.kind, ProblemKind::ManifestInvalid);
        assert!(missing.detail.contains(MANIFEST_FILE));

        std::fs::write(root.join(MANIFEST_FILE), "not: [valid").unwrap();
        let malformed = Bundle::load_sealed(root).unwrap_err();
        assert_eq!(malformed.kind, ProblemKind::ManifestInvalid);
        assert!(malformed.detail.contains("manifest.yaml is not valid"));

        std::fs::write(
            root.join(MANIFEST_FILE),
            "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments: []\n",
        )
        .unwrap();
        let unsealed = Bundle::load_sealed(root).unwrap_err();
        assert_eq!(unsealed.kind, ProblemKind::BundleUnsealed);
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
            "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: notice\n    version: 1\n    entry: templates/notice.typ\n    schema: schemas/notice.schema.json\n    labels: [en]\n",
        )
        .unwrap();
        let entry = root.join("templates/notice.typ");
        let labels = root.join("labels/en.yaml");
        let schema = root.join("schemas/notice.schema.json");
        let font = root.join("fonts/NotoSans-Regular.ttf");
        std::fs::write(&entry, "Captured").unwrap();
        std::fs::write(&labels, "title: Captured\n").unwrap();
        std::fs::write(&schema, r#"{"type":"object"}"#).unwrap();
        std::fs::write(
            &font,
            include_bytes!("../assets/starter-fonts/NotoSans-Regular.ttf"),
        )
        .unwrap();
        Bundle::seal(root).unwrap();

        let (snapshot, manifest, manifest_bytes, _directory) =
            BundleSnapshot::load(root, false).unwrap();
        let expected_hash = sha256_hex(&manifest_bytes);

        // Every path used by assembly changes after capture. Assembly must
        // still parse and validate only the captured bytes.
        std::fs::write(root.join(MANIFEST_FILE), "not the captured manifest").unwrap();
        std::fs::remove_file(&entry).unwrap();
        std::fs::write(&labels, "not: [valid").unwrap();
        std::fs::write(&schema, "not json").unwrap();
        std::fs::write(&font, "not a font").unwrap();

        let bundle = Bundle::assemble(root, manifest, manifest_bytes, snapshot).unwrap();
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
            "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: notice\n    version: 1\n    entry: ./templates//notice.typ\n    schema: schemas//./notice.schema.json\n",
        )
        .unwrap();
        std::fs::write(root.join("templates/notice.typ"), "= Notice").unwrap();
        std::fs::write(
            root.join("schemas/notice.schema.json"),
            r#"{"type":"object"}"#,
        )
        .unwrap();
        Bundle::seal(root).unwrap();

        let bundle = Bundle::load_sealed(root).unwrap();
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
}
