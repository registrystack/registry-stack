//! The bundle manifest: the closed, versioned contract that turns a
//! directory of Typst files, fonts, labels, schemas, and packages into
//! governed content.

use std::fmt;
use std::path::PathBuf;

use registry_platform_yaml::{
    ApiVersion, BoundedU32, Diagnostic, Document, EnvelopeRule, Expect, FormatSpec, Identified,
    LocalId, Reader, RemovedKey, Report, RetiredApiVersion, Severity, UniqueIdList, UniqueList,
};
use serde::{Deserialize, Serialize};

use crate::problem::{ProblemKind, RenderProblem};

pub const MANIFEST_API_VERSION: &str = "id.registrystack.org/formats/render/bundle/v1alpha1";
/// The `apiVersion` bundles wrote before the format moved to
/// id.registrystack.org.
pub const RETIRED_MANIFEST_API_VERSION: &str = "render.registrystack.org/v1alpha1";
pub const MANIFEST_KIND: &str = "RenderBundle";
pub const MANIFEST_FILE: &str = "manifest.yaml";

/// The bundle manifest as the shared reader accepts it.
pub(crate) const MANIFEST_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: MANIFEST_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(MANIFEST_API_VERSION)],
        retired_api_versions: &[RetiredApiVersion {
            api_version: RETIRED_MANIFEST_API_VERSION,
            replacement:
                "Change apiVersion to id.registrystack.org/formats/render/bundle/v1alpha1, \
                          rename each document's entry to entryFile and schema to schemaFile, and \
                          give each label file the RenderLabels envelope.",
        }],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/hashes",
            replacement: "Remove hashes, and build a deployment package with \
                          `registry-render package --bundle <source> --output <directory>`.",
        },
        RemovedKey {
            pointer: "/documents/*/entry",
            replacement: "Rename entry to entryFile; the value is unchanged.",
        },
        RemovedKey {
            pointer: "/documents/*/schema",
            replacement: "Rename schema to schemaFile; the value is unchanged.",
        },
    ],
};

/// The PDF standard a document is rendered under. Mirrors the Typst CLI's
/// spellings exactly so bundles and CLI examples agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// `manifest.yaml`: the document types a bundle declares.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ManifestFile {
    pub(crate) api_version: String,
    pub(crate) kind: String,
    /// Author-defined bundle version, monotonic per bundle.
    pub(crate) bundle_version: BoundedU32<0, { u32::MAX }>,
    /// The document types, each with an id unique in the bundle.
    #[serde(default)]
    pub(crate) documents: UniqueIdList<DocumentFile>,
}

/// One document type as `manifest.yaml` writes it.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct DocumentFile {
    /// Stable document identifier used in requests and routes.
    pub(crate) id: LocalId,
    /// The document's own version; printed on paper by templates that wish to.
    pub(crate) version: BoundedU32<0, { u32::MAX }>,
    /// Entry point relative to the bundle root: a `.typ` file inside the
    /// bundle.
    pub(crate) entry_file: String,
    /// JSON Schema (draft 2020-12) for the request data, relative to the
    /// bundle root: a `.json` file inside the bundle.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub(crate) schema_file: Option<String>,
    /// Label tables the template receives, by locale: each names
    /// `labels/<locale>.yaml`.
    #[serde(default)]
    pub(crate) labels: UniqueList<LocalId>,
    /// PDF standard for this document; plain PDF when absent.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(with = "PdfStandardSpec"))]
    pub(crate) pdf_standard: Option<PdfStandardSpec>,
}

impl Identified for DocumentFile {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// One document type in a bundle.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentSpec {
    /// Stable document identifier used in requests and routes.
    pub id: String,
    /// The document's own version; printed on paper by templates that wish to.
    pub version: u32,
    /// Entry point relative to the bundle root (a `.typ` file), as
    /// `entryFile` writes it.
    #[serde(rename = "entryFile")]
    pub entry: PathBuf,
    /// JSON Schema (draft 2020-12) for the request data, relative to root,
    /// as `schemaFile` writes it.
    #[serde(rename = "schemaFile", skip_serializing_if = "Option::is_none")]
    pub schema: Option<PathBuf>,
    /// Label tables (in `labels/`) the template receives, by locale.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// PDF standard for this document; `None` means plain PDF.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_standard: Option<PdfStandardSpec>,
}

impl DocumentSpec {
    /// The locale names implied by the declared label tables.
    pub fn locales(&self) -> &[String] {
        &self.labels
    }
}

/// The full bundle manifest.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub api_version: String,
    pub kind: String,
    /// Author-defined bundle version, monotonic per bundle.
    pub bundle_version: u32,
    pub documents: Vec<DocumentSpec>,
}

/// A manifest the reader accepted, with the document its findings are
/// placed in.
#[derive(Debug, Clone)]
pub(crate) struct ReadManifest {
    pub(crate) manifest: Manifest,
    pub(crate) document: Document,
}

/// Read `manifest.yaml` through the shared reader, refusing every `${...}`
/// expression (CFG-SEC-2), and check each document's file paths. `file` is
/// the name every diagnostic carries.
pub(crate) fn read_manifest(file: &str, bytes: &[u8]) -> Result<ReadManifest, Report> {
    let mut hook = registry_platform_config::AuthoredExpressions;
    let decoded = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<ManifestFile>(bytes, &Expect::one(&MANIFEST_FORMAT))?;
    let document = decoded.document;
    let mut findings = document.warnings();
    for (index, spec) in decoded.value.documents.iter().enumerate() {
        if !is_bundle_path(&spec.entry_file, ".typ") {
            findings.push(error_at(
                &document,
                "render.bundle.invalid-entry-file",
                &format!("/documents/{index}/entryFile"),
                "the entry file must be a relative .typ path inside the bundle",
                "Name a .typ file under the bundle directory, without `..` or a leading `/`.",
            ));
        }
        if let Some(schema) = &spec.schema_file {
            // The schema gets the same containment rule as the entry: a
            // schema outside the bundle would sit outside package governance.
            if !is_bundle_path(schema, ".json") {
                findings.push(error_at(
                    &document,
                    "render.bundle.invalid-schema-file",
                    &format!("/documents/{index}/schemaFile"),
                    "the schema file must be a relative .json path inside the bundle",
                    "Name a .json file under the bundle directory, without `..` or a leading `/`.",
                ));
            }
        }
    }
    if findings.has_errors() {
        return Err(findings);
    }
    let file = decoded.value;
    let manifest = Manifest {
        api_version: file.api_version,
        kind: file.kind,
        bundle_version: file.bundle_version.get(),
        documents: file
            .documents
            .into_vec()
            .into_iter()
            .map(|spec| DocumentSpec {
                id: spec.id.into_string(),
                version: spec.version.get(),
                entry: PathBuf::from(spec.entry_file),
                schema: spec.schema_file.map(PathBuf::from),
                labels: spec
                    .labels
                    .into_vec()
                    .into_iter()
                    .map(LocalId::into_string)
                    .collect(),
                pdf_standard: spec.pdf_standard,
            })
            .collect(),
    };
    Ok(ReadManifest { manifest, document })
}

/// An error placed at the value of the member at `pointer`.
pub(crate) fn error_at(
    document: &Document,
    code: &str,
    pointer: &str,
    message: &str,
    action: &str,
) -> Diagnostic {
    document.diagnostic_at_value(Severity::Error, code, pointer, message, action)
}

/// A relative path with the given suffix that stays inside the bundle.
fn is_bundle_path(path: &str, suffix: &str) -> bool {
    !path.is_empty() && path.ends_with(suffix) && !path.contains("..") && !path.starts_with('/')
}

/// The problem Render reports when the shared reader refused `file`: one
/// sentence of its own, then the reader's diagnostics unchanged.
pub(crate) fn refused(kind: ProblemKind, file: &str, report: Report) -> RenderProblem {
    RenderProblem::new(kind, format!("{file} was refused"))
        .with_diagnostics(report.into_diagnostics())
}

impl Manifest {
    /// Read manifest bytes through the shared reader and check them; the
    /// diagnostics name the file `manifest.yaml`.
    pub fn parse(bytes: &[u8]) -> Result<Self, RenderProblem> {
        read_manifest(MANIFEST_FILE, bytes)
            .map(|read| read.manifest)
            .map_err(|report| refused(ProblemKind::ManifestInvalid, MANIFEST_FILE, report))
    }

    pub fn document(&self, id: &str) -> Result<&DocumentSpec, RenderProblem> {
        self.documents.iter().find(|d| d.id == id).ok_or_else(|| {
            RenderProblem::new(
                ProblemKind::UnknownDocument,
                format!("bundle has no document type {id:?}"),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str =
        "apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1\nkind: RenderBundle\n";

    fn refused_codes(text: &str) -> Vec<(String, String)> {
        let problem = Manifest::parse(text.as_bytes()).expect_err("refused");
        assert_eq!(problem.kind, ProblemKind::ManifestInvalid);
        problem
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect()
    }

    #[test]
    fn rejects_unknown_fields_and_wrong_kind() {
        let bad = "apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1\nkind: Other\nbundleVersion: 1\n";
        assert!(Manifest::parse(bad.as_bytes()).is_err());
        let unknown = format!("{HEAD}bundleVersion: 1\nextra: 1\n");
        assert_eq!(
            refused_codes(&unknown),
            [("config.unknown-key".to_owned(), "/extra".to_owned())]
        );
    }

    #[test]
    fn cfg_diag_5_two_unknown_keys_are_both_reported() {
        let text = format!(
            "{HEAD}bundleVersion: 1\ndocuments:\n  - id: d\n    version: 1\n    entryFile: templates/d.typ\n    colour: red\n    size: 2\n"
        );
        assert_eq!(
            refused_codes(&text),
            [
                (
                    "config.unknown-key".to_owned(),
                    "/documents/0/colour".to_owned()
                ),
                (
                    "config.unknown-key".to_owned(),
                    "/documents/0/size".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn schema_path_is_validated_like_the_entry() {
        // A schema outside the bundle sits outside the package; the entry rule
        // (no `..`, no absolute, correct suffix) applies to it too.
        let doc = |schema: &str| {
            format!("{HEAD}bundleVersion: 1\ndocuments:\n  - id: d\n    version: 1\n    entryFile: templates/d.typ\n    schemaFile: {schema}\n")
        };
        assert!(Manifest::parse(doc("schemas/d.schema.json").as_bytes()).is_ok());
        for bad in [
            "../outside.schema.json",
            "/etc/evil.schema.json",
            "schemas/d.yaml",
        ] {
            assert_eq!(
                refused_codes(&doc(bad)),
                [(
                    "render.bundle.invalid-schema-file".to_owned(),
                    "/documents/0/schemaFile".to_owned()
                )]
            );
        }
    }

    #[test]
    fn every_path_finding_is_reported_at_its_value() {
        let text = format!(
            "{HEAD}bundleVersion: 1\ndocuments:\n  - id: a\n    version: 1\n    entryFile: ../a.typ\n  - id: b\n    version: 1\n    entryFile: templates/b.txt\n    schemaFile: /b.json\n"
        );
        let problem = Manifest::parse(text.as_bytes()).expect_err("refused");
        let found: Vec<_> = problem
            .diagnostics
            .iter()
            .map(|diagnostic| {
                let source = diagnostic.source.as_ref().unwrap();
                (
                    diagnostic.code.as_str(),
                    source.file.as_str(),
                    source.line,
                    source.column,
                )
            })
            .collect();
        assert_eq!(
            found,
            [
                (
                    "render.bundle.invalid-entry-file",
                    MANIFEST_FILE,
                    Some(7),
                    Some(16)
                ),
                (
                    "render.bundle.invalid-entry-file",
                    MANIFEST_FILE,
                    Some(10),
                    Some(16)
                ),
                (
                    "render.bundle.invalid-schema-file",
                    MANIFEST_FILE,
                    Some(11),
                    Some(17)
                ),
            ]
        );
        assert_eq!(
            problem.diagnostics[0].artifact.as_deref(),
            Some(MANIFEST_KIND)
        );
    }

    #[test]
    fn parses_minimal_manifest() {
        let good = format!("{HEAD}bundleVersion: 3\ndocuments:\n  - id: receipt\n    version: 3\n    entryFile: templates/receipt.typ\n    labels: [ar, fr]\n");
        let m = Manifest::parse(good.as_bytes()).expect("parses");
        assert_eq!(m.documents.len(), 1);
        assert_eq!(m.documents[0].labels, vec!["ar", "fr"]);
        assert_eq!(m.documents[0].pdf_standard.map(|s| s.to_string()), None);
    }

    #[test]
    fn duplicate_document_ids_and_labels_are_refused_at_the_repeat() {
        let labels = format!(
            "{HEAD}bundleVersion: 1\ndocuments:\n  - id: d\n    version: 1\n    entryFile: templates/d.typ\n    labels: [en, en]\n"
        );
        assert_eq!(
            refused_codes(&labels),
            [(
                "config.duplicate-item".to_owned(),
                "/documents/0/labels/1".to_owned()
            )]
        );
        let ids = format!(
            "{HEAD}bundleVersion: 1\ndocuments:\n  - id: d\n    version: 1\n    entryFile: templates/d.typ\n  - id: d\n    version: 1\n    entryFile: templates/d.typ\n"
        );
        assert_eq!(
            refused_codes(&ids),
            [(
                "config.duplicate-id".to_owned(),
                "/documents/1/id".to_owned()
            )]
        );
    }

    #[test]
    fn retired_manifest_keys_name_their_replacement() {
        let manifest = format!("{HEAD}bundleVersion: 1\ndocuments:\n  - id: d\n    version: 1\n    entry: templates/d.typ\n    schema: schemas/d.json\nhashes:\n  templates/a.typ: aaaa\n");
        let problem = Manifest::parse(manifest.as_bytes()).expect_err("retired keys");
        let found: Vec<_> = problem
            .diagnostics
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic.code.as_str(),
                    diagnostic.path.as_str(),
                    diagnostic.suggested_action.as_str(),
                )
            })
            .collect();
        // The document also lacks the entryFile its entry was renamed to.
        assert_eq!(
            found,
            [
                ("config.missing-key", "/documents/0", "Add `entryFile`."),
                (
                    "config.removed-key",
                    "/documents/0/entry",
                    "Rename entry to entryFile; the value is unchanged."
                ),
                (
                    "config.removed-key",
                    "/documents/0/schema",
                    "Rename schema to schemaFile; the value is unchanged."
                ),
                (
                    "config.removed-key",
                    "/hashes",
                    "Remove hashes, and build a deployment package with `registry-render package --bundle <source> --output <directory>`."
                ),
            ]
        );
    }

    #[test]
    fn cfg_change_2_the_retired_api_version_names_the_new_one() {
        let manifest =
            "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderBundle\nbundleVersion: 1\n";
        let problem = Manifest::parse(manifest.as_bytes()).expect_err("retired");
        assert_eq!(problem.diagnostics[0].code, "config.retired-api-version");
        assert!(problem.diagnostics[0]
            .suggested_action
            .contains(MANIFEST_API_VERSION));
    }

    #[test]
    fn pdf_standard_roundtrip_kebab() {
        let good = format!("{HEAD}bundleVersion: 1\ndocuments:\n  - id: cert\n    version: 1\n    entryFile: templates/cert.typ\n    pdfStandard: a-4\n");
        let m = Manifest::parse(good.as_bytes()).expect("parses");
        assert_eq!(m.documents[0].pdf_standard, Some(PdfStandardSpec::A4));
        assert_eq!(PdfStandardSpec::A4.to_typst(), typst_pdf::PdfStandard::A_4);
        assert_eq!(
            PdfStandardSpec::V1_7.to_typst(),
            typst_pdf::PdfStandard::V_1_7
        );
    }

    #[test]
    fn cfg_sec_2_an_authored_manifest_carrying_an_environment_expression_is_refused() {
        let manifest = format!("{HEAD}bundleVersion: 1\ndocuments:\n  - id: receipt\n    version: 1\n    entryFile: templates/${{DOCUMENT}}.typ\n");
        assert_eq!(
            refused_codes(&manifest),
            [(
                "config.substitution-not-allowed".to_owned(),
                "/documents/0/entryFile".to_owned()
            )]
        );
    }
}
