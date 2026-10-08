//! The export manifest, `source-export.json`, read through the shared
//! configuration reader.

use std::collections::BTreeMap;

use registry_platform_yaml::{
    ApiVersion, Digest, EnvelopeRule, Expect, FormatSpec, Reader, RemovedKey, Report,
};
use serde::Deserialize;

/// The `apiVersion` of an Evidence source export manifest. `bregctl generate
/// evidence-source` writes the same value.
pub(crate) const EXPORT_API_VERSION: &str =
    "id.registrystack.org/formats/breg/evidence-source-export/v1alpha1";
pub(crate) const EXPORT_KIND: &str = "BRegEvidenceSourceExport";

const EXPORT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: EXPORT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(EXPORT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/formatVersion",
            replacement: "Delete `formatVersion`; `apiVersion` replaces it.",
        },
        RemovedKey {
            pointer: "/artifacts/*/sha256",
            replacement: "Rename `sha256` to `digest`, written as `sha256:` followed by the \
                          64 lowercase hex digits.",
        },
    ],
};

/// A document the shared reader refused, such as a `source-export.json`. Its
/// diagnostics are printed unchanged, in the human or the JSON shape the
/// command was asked for.
#[derive(Debug)]
pub(crate) struct DocumentRefused {
    /// What the document is, for the sentence that introduces the diagnostics.
    pub(crate) document: &'static str,
    pub(crate) report: Report,
}

impl std::fmt::Display for DocumentRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "the {} was refused.\n{}",
            self.document,
            self.report.render_human()
        )
    }
}

impl std::error::Error for DocumentRefused {}

/// The export manifest as written. The reader checks and strips its
/// `apiVersion` and `kind`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExportDocument {
    pub(super) source_id: String,
    pub(super) provenance: BTreeMap<String, String>,
    pub(super) artifacts: Vec<ExportDocumentArtifact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExportDocumentArtifact {
    pub(super) path: String,
    pub(super) digest: Digest,
}

/// Decode `bytes`, the manifest at `file`, refusing it with the reader's
/// diagnostics.
pub(super) fn read_export_manifest(
    file: &str,
    bytes: &[u8],
) -> Result<ExportDocument, DocumentRefused> {
    Reader::new(file)
        .decode::<ExportDocument>(bytes, &Expect::one(&EXPORT_FORMAT))
        .map(|decoded| decoded.value)
        .map_err(|report| DocumentRefused {
            document: "Evidence source export manifest",
            report,
        })
}
