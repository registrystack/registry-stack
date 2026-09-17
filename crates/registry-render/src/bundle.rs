//! Bundle loading, verification, and sealing. A bundle is a directory: one
//! `manifest.yaml` plus the templates, labels, schemas, fonts, and vendored
//! packages it governs. Sealing hashes every governed file; serving requires
//! a sealed bundle, compiling does not.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

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
}

impl Bundle {
    /// Load a bundle without requiring it to be sealed. If it is sealed, the
    /// hashes are verified.
    pub fn load(root: &Path) -> Result<Self, RenderProblem> {
        let (manifest, manifest_bytes) = read_manifest(root)?;
        if manifest.is_sealed() {
            verify_hashes(root, &manifest)?;
        }
        Self::assemble(root, manifest, manifest_bytes)
    }

    /// Load a bundle and require a verified seal.
    pub fn load_sealed(root: &Path) -> Result<Self, RenderProblem> {
        let (manifest, manifest_bytes) = read_manifest(root)?;
        if !manifest.is_sealed() {
            return Err(RenderProblem::new(
                ProblemKind::BundleUnsealed,
                "serve requires a sealed bundle; run `render seal` first",
            ));
        }
        verify_hashes(root, &manifest)?;
        Self::assemble(root, manifest, manifest_bytes)
    }

    fn assemble(
        root: &Path,
        manifest: Manifest,
        manifest_bytes: Vec<u8>,
    ) -> Result<Self, RenderProblem> {
        let bundle_hash = sha256_hex(&manifest_bytes);
        let mut documents = BTreeMap::new();
        for spec in manifest.documents.clone() {
            let mut labels = BTreeMap::new();
            for locale in &spec.labels {
                let path = root.join("labels").join(format!("{locale}.yaml"));
                let bytes = std::fs::read(&path).map_err(|err| {
                    RenderProblem::new(
                        ProblemKind::LabelsInvalid,
                        format!("document {:?} declares label {locale:?}: {err}", spec.id),
                    )
                    .with_locations(vec![format!("labels/{locale}.yaml")])
                })?;
                let table: Value = serde_norway::from_slice(&bytes).map_err(|err| {
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
                    let path = root.join(rel);
                    let bytes = std::fs::read(&path).map_err(|err| {
                        RenderProblem::new(
                            ProblemKind::ManifestInvalid,
                            format!("document {:?} schema {}: {err}", spec.id, rel.display()),
                        )
                    })?;
                    let value: Value = serde_json::from_slice(&bytes).map_err(|err| {
                        RenderProblem::new(
                            ProblemKind::ManifestInvalid,
                            format!("schema {} is not valid JSON: {err}", rel.display()),
                        )
                    })?;
                    Some(value)
                }
            };
            // The entry file must exist; the world reads it during render but
            // failing here gives a plain problem instead of a compile one.
            let entry = root.join(&spec.entry);
            if !entry.is_file() {
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
        let fonts = load_fonts(root)?;
        Ok(Self {
            root: root.canonicalize().unwrap_or_else(|_| root.to_path_buf()),
            manifest,
            manifest_bytes,
            bundle_hash,
            documents,
            fonts,
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
        let (mut manifest, _) = read_manifest(root)?;
        let hashes = Manifest::compute_hashes(root)?;
        manifest.hashes = Some(hashes);
        let serialized = serde_norway::to_string(&manifest).map_err(|err| {
            RenderProblem::new(
                ProblemKind::Internal,
                format!("cannot serialize manifest: {err}"),
            )
        })?;
        let target = root.join(MANIFEST_FILE);
        std::fs::write(&target, serialized).map_err(|err| {
            RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!("cannot write {}: {err}", target.display()),
            )
        })?;
        Ok(manifest)
    }
}

fn read_manifest(root: &Path) -> Result<(Manifest, Vec<u8>), RenderProblem> {
    let path = root.join(MANIFEST_FILE);
    let bytes = std::fs::read(&path).map_err(|err| {
        RenderProblem::new(
            ProblemKind::ManifestInvalid,
            format!("cannot read {}: {err}", path.display()),
        )
    })?;
    let manifest = Manifest::parse(&bytes)?;
    Ok((manifest, bytes))
}

fn verify_hashes(root: &Path, manifest: &Manifest) -> Result<(), RenderProblem> {
    let declared = manifest.hashes.as_ref().expect("caller checked is_sealed");
    let actual = Manifest::compute_hashes(root)?;
    let mut mismatches = Vec::new();
    for (rel, want) in declared {
        match actual.get(rel) {
            Some(got) if got == want => {}
            Some(_) => mismatches.push(format!("{rel} (content changed)")),
            None => mismatches.push(format!("{rel} (missing)")),
        }
    }
    for rel in actual.keys() {
        if !declared.contains_key(rel) {
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

/// Bundle fonts sorted by relative path, then the baseline set embedded in
/// the binary. The order is part of byte stability: it decides font
/// fallback, so it may never depend on filesystem iteration order.
pub fn load_fonts(root: &Path) -> Result<Vec<typst::text::Font>, RenderProblem> {
    let mut fonts = Vec::new();
    let fonts_dir = root.join("fonts");
    let mut files = Vec::new();
    if fonts_dir.is_dir() {
        let entries = std::fs::read_dir(&fonts_dir).map_err(|err| {
            RenderProblem::new(
                ProblemKind::FontInvalid,
                format!("cannot read fonts directory: {err}"),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|err| {
                RenderProblem::new(
                    ProblemKind::FontInvalid,
                    format!("cannot read fonts directory: {err}"),
                )
            })?;
            let path = entry.path();
            // Only font files load; license texts commonly live beside the
            // fonts they govern (the example bundles ship OFL.txt).
            let is_font_file = path.is_file()
                && path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                    matches!(
                        e.to_ascii_lowercase().as_str(),
                        "ttf" | "otf" | "ttc" | "woff" | "woff2"
                    )
                });
            if is_font_file {
                files.push(path);
            }
        }
    }
    files.sort();
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
    for path in files {
        let bytes = std::fs::read(&path).map_err(|err| {
            RenderProblem::new(
                ProblemKind::FontInvalid,
                format!("cannot read font {}: {err}", path.display()),
            )
        })?;
        let data = typst::foundations::Bytes::new(bytes);
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
                    path.file_name()
                        .map(|n| n.to_string_lossy())
                        .unwrap_or_default()
                ),
            ));
        }
    }
    Ok(fonts)
}
