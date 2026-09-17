//! The bundle manifest: the closed, versioned contract that turns a
//! directory of Typst files, fonts, labels, schemas, and packages into
//! governed content.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::problem::{ProblemKind, RenderProblem};

pub const MANIFEST_API_VERSION: &str = "render.registrystack.org/v1alpha1";
pub const MANIFEST_KIND: &str = "RenderBundle";
pub const MANIFEST_FILE: &str = "manifest.yaml";

/// The PDF standard a document is rendered under. Mirrors the Typst CLI's
/// spellings exactly so bundles and CLI examples agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PdfStandardSpec {
    #[serde(rename = "1.4")]
    V1_4,
    #[serde(rename = "1.5")]
    V1_5,
    #[serde(rename = "1.6")]
    V1_6,
    #[serde(rename = "1.7")]
    V1_7,
    #[serde(rename = "2.0")]
    V2_0,
    #[serde(rename = "a-1b")]
    A1b,
    #[serde(rename = "a-1a")]
    A1a,
    #[serde(rename = "a-2b")]
    A2b,
    #[serde(rename = "a-2u")]
    A2u,
    #[serde(rename = "a-2a")]
    A2a,
    #[serde(rename = "a-3b")]
    A3b,
    #[serde(rename = "a-3u")]
    A3u,
    #[serde(rename = "a-3a")]
    A3a,
    #[serde(rename = "a-4")]
    A4,
    #[serde(rename = "a-4f")]
    A4f,
    #[serde(rename = "a-4e")]
    A4e,
    #[serde(rename = "ua-1")]
    Ua1,
}

impl PdfStandardSpec {
    /// Map to the rendering crate's standard enum. The mapping is total and
    /// reviewed by the golden tests: a spec here must render identically on
    /// every platform.
    pub fn to_typst(self) -> typst_pdf::PdfStandard {
        use typst_pdf::PdfStandard as T;
        match self {
            Self::V1_4 => T::V_1_4,
            Self::V1_5 => T::V_1_5,
            Self::V1_6 => T::V_1_6,
            Self::V1_7 => T::V_1_7,
            Self::V2_0 => T::V_2_0,
            Self::A1b => T::A_1b,
            Self::A1a => T::A_1a,
            Self::A2b => T::A_2b,
            Self::A2u => T::A_2u,
            Self::A2a => T::A_2a,
            Self::A3b => T::A_3b,
            Self::A3u => T::A_3u,
            Self::A3a => T::A_3a,
            Self::A4 => T::A_4,
            Self::A4f => T::A_4f,
            Self::A4e => T::A_4e,
            Self::Ua1 => T::Ua_1,
        }
    }
}

impl fmt::Display for PdfStandardSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned));
        match s {
            Some(s) => f.write_str(&s),
            None => f.write_str("?"),
        }
    }
}

/// One document type in a bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DocumentSpec {
    /// Stable document identifier used in requests and routes.
    pub id: String,
    /// The document's own version; printed on paper by templates that wish to.
    pub version: u32,
    /// Entry point relative to the bundle root (a `.typ` file).
    pub entry: PathBuf,
    /// JSON Schema (draft 2020-12) for the request data, relative to root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<PathBuf>,
    /// Label tables (in `labels/`) the template receives, by locale.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// PDF standard for this document; `None` means plain PDF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdf_standard: Option<PdfStandardSpec>,
}

impl DocumentSpec {
    /// The locale names implied by the declared label tables.
    pub fn locales(&self) -> &[String] {
        &self.labels
    }
}

/// The full bundle manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Manifest {
    pub api_version: String,
    pub kind: String,
    /// Author-defined bundle version, monotonic per bundle.
    pub bundle_version: u32,
    #[serde(default, rename = "documents")]
    pub documents: Vec<DocumentSpec>,
    /// Per-file sha256 hex digests, relative to the bundle root, slash
    /// separated. Present iff the bundle is sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<BTreeMap<String, String>>,
}

impl Manifest {
    /// Parse and structurally validate manifest bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, RenderProblem> {
        let manifest: Manifest = serde_norway::from_slice(bytes).map_err(|err| {
            RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!("manifest.yaml is not valid: {err}"),
            )
        })?;
        if manifest.api_version != MANIFEST_API_VERSION {
            return Err(RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!(
                    "manifest apiVersion must be {MANIFEST_API_VERSION}, found {}",
                    manifest.api_version
                ),
            ));
        }
        if manifest.kind != MANIFEST_KIND {
            return Err(RenderProblem::new(
                ProblemKind::ManifestInvalid,
                format!(
                    "manifest kind must be {MANIFEST_KIND}, found {}",
                    manifest.kind
                ),
            ));
        }
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), RenderProblem> {
        let mut seen = std::collections::BTreeSet::new();
        for doc in &self.documents {
            if doc.id.is_empty()
                || !doc
                    .id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(RenderProblem::new(
                    ProblemKind::ManifestInvalid,
                    format!(
                        "document id must be lowercase kebab-case, found {:?}",
                        doc.id
                    ),
                ));
            }
            if !seen.insert(doc.id.as_str()) {
                return Err(RenderProblem::new(
                    ProblemKind::ManifestInvalid,
                    format!("duplicate document id {:?}", doc.id),
                ));
            }
            let entry = doc.entry.to_string_lossy();
            if entry.is_empty()
                || !entry.ends_with(".typ")
                || entry.contains("..")
                || entry.starts_with('/')
            {
                return Err(RenderProblem::new(
                    ProblemKind::ManifestInvalid,
                    format!(
                        "document {:?} entry must be a .typ path inside the bundle",
                        doc.id
                    ),
                ));
            }
            // The schema gets the same containment rule as the entry: a
            // schema outside the bundle would sit outside the seal.
            if let Some(schema) = doc.schema.as_ref() {
                let schema = schema.to_string_lossy();
                if schema.is_empty()
                    || !schema.ends_with(".json")
                    || schema.contains("..")
                    || schema.starts_with('/')
                {
                    return Err(RenderProblem::new(
                        ProblemKind::ManifestInvalid,
                        format!(
                            "document {:?} schema must be a .json path inside the bundle",
                            doc.id
                        ),
                    ));
                }
            }
            for locale in &doc.labels {
                if locale.is_empty()
                    || !locale
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                {
                    return Err(RenderProblem::new(
                        ProblemKind::ManifestInvalid,
                        format!(
                            "document {:?} label name must be kebab-case, found {:?}",
                            doc.id, locale
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn document(&self, id: &str) -> Result<&DocumentSpec, RenderProblem> {
        self.documents.iter().find(|d| d.id == id).ok_or_else(|| {
            RenderProblem::new(
                ProblemKind::UnknownDocument,
                format!("bundle has no document type {id:?}"),
            )
        })
    }

    pub fn is_sealed(&self) -> bool {
        self.hashes.as_ref().is_some_and(|h| !h.is_empty())
    }

    /// Compute the per-file sha256 map over every governed file in the
    /// bundle. `manifest.yaml` itself is excluded: it carries the hashes
    /// and cannot hash itself; the bundle id is the sha256 of the sealed
    /// manifest bytes. Deterministic: sorted relative paths,
    /// slash-separated.
    pub fn compute_hashes(root: &Path) -> Result<BTreeMap<String, String>, RenderProblem> {
        let mut map = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir).map_err(|err| {
                RenderProblem::new(
                    ProblemKind::ManifestInvalid,
                    format!("cannot read bundle directory {}: {err}", dir.display()),
                )
            })?;
            for entry in entries {
                let entry = entry.map_err(|err| {
                    RenderProblem::new(
                        ProblemKind::ManifestInvalid,
                        format!("cannot read bundle directory {}: {err}", dir.display()),
                    )
                })?;
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path).map_err(|err| {
                    RenderProblem::new(
                        ProblemKind::ManifestInvalid,
                        format!("cannot stat {}: {err}", path.display()),
                    )
                })?;
                let file_type = meta.file_type();
                if file_type.is_symlink() {
                    // A symlink inside the bundle could point outside the
                    // root; the render world refuses it, so a seal that
                    // silently hashed its target would produce a bundle
                    // that verifies but cannot render.
                    return Err(RenderProblem::new(
                        ProblemKind::ManifestInvalid,
                        format!(
                            "bundle contains a symlink, which cannot be sealed: {}",
                            path.display()
                        ),
                    ));
                }
                if file_type.is_dir() {
                    stack.push(path);
                } else {
                    let bytes = std::fs::read(&path).map_err(|err| {
                        RenderProblem::new(
                            ProblemKind::ManifestInvalid,
                            format!("cannot read {}: {err}", path.display()),
                        )
                    })?;
                    let rel = path
                        .strip_prefix(root)
                        .expect("walk stays under root")
                        .to_string_lossy()
                        .replace('\\', "/");
                    // Only the bundle's own root manifest is excluded (it
                    // carries these hashes); a nested manifest.yaml is
                    // ordinary governed content.
                    if rel == MANIFEST_FILE {
                        continue;
                    }
                    let digest = crate::hash::sha256_hex(&bytes);
                    map.insert(rel, digest);
                }
            }
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields_and_wrong_kind() {
        let bad = b"apiVersion: render.registrystack.org/v1alpha1\nkind: Other\nbundleVersion: 1\n";
        assert!(Manifest::parse(bad).is_err());
        let unknown = b"apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\nextra: 1\n";
        assert!(Manifest::parse(unknown).is_err());
    }

    #[test]
    fn schema_path_is_validated_like_the_entry() {
        // A schema outside the bundle sits outside the seal; the entry rule
        // (no `..`, no absolute, correct suffix) applies to it too.
        let doc = |schema: &str| {
            format!("apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: d\n    version: 1\n    entry: templates/d.typ\n    schema: {schema}\n")
        };
        assert!(Manifest::parse(doc("schemas/d.schema.json").as_bytes()).is_ok());
        assert!(Manifest::parse(doc("../outside.schema.json").as_bytes()).is_err());
        assert!(Manifest::parse(doc("/etc/evil.schema.json").as_bytes()).is_err());
        assert!(Manifest::parse(doc("schemas/d.yaml").as_bytes()).is_err());
    }

    #[test]
    fn parses_minimal_manifest() {
        let good = b"apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 3\ndocuments:\n  - id: receipt\n    version: 3\n    entry: templates/receipt.typ\n    labels: [ar, fr]\n";
        let m = Manifest::parse(good).expect("parses");
        assert_eq!(m.documents.len(), 1);
        assert_eq!(m.documents[0].labels, vec!["ar", "fr"]);
        assert!(!m.is_sealed());
        assert_eq!(m.documents[0].pdf_standard.map(|s| s.to_string()), None);
    }

    #[test]
    fn pdf_standard_roundtrip_kebab() {
        let good = b"apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\ndocuments:\n  - id: cert\n    version: 1\n    entry: templates/cert.typ\n    pdfStandard: a-4\n";
        let m = Manifest::parse(good).expect("parses");
        assert_eq!(m.documents[0].pdf_standard, Some(PdfStandardSpec::A4));
        assert_eq!(PdfStandardSpec::A4.to_typst(), typst_pdf::PdfStandard::A_4);
        assert_eq!(
            PdfStandardSpec::V1_7.to_typst(),
            typst_pdf::PdfStandard::V_1_7
        );
    }
}
