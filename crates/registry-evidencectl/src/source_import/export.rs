//! The export manifest, `source-export.json`, read through the shared
//! configuration reader.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context as _, Result};
use registry_evidence_authoring::formats::{decode_authored, SELECTOR_FRAGMENT, SOURCE_FRAGMENT};
use registry_platform_yaml::{
    ApiVersion, Digest, EnvelopeRule, Expect, FormatSpec, Reader, RemovedKey, Report,
};
use serde::Deserialize;
use serde_json::{json, Value};

/// The `apiVersion` of an Evidence source export manifest. `bregctl generate
/// evidence-source` writes the same value.
pub(crate) const EXPORT_API_VERSION: &str =
    "id.registrystack.org/formats/breg/evidence-source-export/v1alpha1";
pub(crate) const EXPORT_KIND: &str = "BRegEvidenceSourceExport";

pub(crate) const EXPORT_FORMAT: FormatSpec<'static> = FormatSpec {
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

pub(super) fn decode_adapter_pack(
    path: &str,
    text: &str,
) -> Result<registry_adapter_core::AdapterPack> {
    let format = FormatSpec {
        kind: registry_adapter_core::ADAPTER_PACK_KIND,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(
                registry_adapter_core::ADAPTER_PACK_API_VERSION,
            )],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };
    Reader::new(path)
        .decode::<registry_adapter_core::AdapterPack>(text.as_bytes(), &Expect::one(&format))
        .map(|decoded| decoded.value)
        .map_err(|report| anyhow!("Adapter pack was refused:\n{}", report.render_human()))
}

/// Normalize one current pack-backed source export. Pack route logic remains
/// in its exact digest-pinned closure; the importer adds no executable
/// compatibility Function and contributes no AssertionDefinition or grant.
pub(super) fn normalize_artifacts(
    source_id: &str,
    artifacts: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let source_path = format!("sources/{source_id}.yaml");
    let source_value = fragment_value(
        &source_path,
        artifacts
            .get(&source_path)
            .ok_or_else(|| anyhow!("source export is missing {source_path}"))?,
        &SOURCE_FRAGMENT,
        "Evidence source fragment",
    )?;
    let source = serde_json::from_value::<registry_evidence_authoring::project::Source>(
        source_value.clone(),
    )
    .context("the exported Source does not fit the current pack binding")?;
    let pack_root = format!("adapter-packs/{}", source.pack.id);
    let pack_path = format!("{pack_root}/pack.yaml");
    let pack_text = artifacts
        .get(&pack_path)
        .ok_or_else(|| anyhow!("source export is missing {pack_path}"))?;
    let pack = decode_adapter_pack(&pack_path, pack_text)?;
    if pack.id != source.pack.id || pack.version != source.pack.version {
        bail!("exported Source and Adapter pack identity must agree");
    }
    let route = pack
        .source_routes
        .get(source.route.as_str())
        .ok_or_else(|| {
            anyhow!("exported Adapter pack does not declare the selected source route")
        })?;
    let evidence = route
        .evidence
        .as_ref()
        .ok_or_else(|| anyhow!("exported source route requires an Evidence contract"))?;
    if serde_json::to_value(evidence.acquisition_posture)?
        != serde_json::to_value(source.acquisition_posture)?
    {
        bail!("exported Source posture must equal its pinned route contract");
    }

    let mut expected = BTreeMap::from([(source_path.clone(), ()), (pack_path.clone(), ())]);
    let mut pins = BTreeMap::new();
    for reference in pack.pinned_files() {
        if let Some(existing) = pins.insert(reference.path.as_str(), reference.digest.as_str()) {
            if existing != reference.digest.as_str() {
                bail!("exported Adapter pack has conflicting pins for one artifact path");
            }
        }
        let path = format!("{pack_root}/{}", reference.path);
        let text = artifacts
            .get(&path)
            .ok_or_else(|| anyhow!("source export is missing pinned pack artifact {path}"))?;
        if super::files::digest(text.as_bytes()) != reference.digest.hex() {
            bail!("exported Adapter pack artifact does not match its digest pin: {path}");
        }
        expected.insert(path, ());
    }

    let mut selector_profiles = BTreeMap::new();
    for path in artifacts
        .keys()
        .filter(|path| path.starts_with("selectors/") && path.ends_with(".yaml"))
    {
        let id = path
            .trim_start_matches("selectors/")
            .trim_end_matches(".yaml");
        let profile = fragment_value(
            path,
            &artifacts[path],
            &SELECTOR_FRAGMENT,
            "Evidence selector fragment",
        )?;
        profile
            .as_object()
            .ok_or_else(|| anyhow!("exported SelectorProfile must be a mapping"))?;
        let profile =
            serde_json::from_value::<registry_evidence_authoring::project::SelectorProfile>(
                profile,
            )
            .with_context(|| format!("{path} does not fit EvidenceProject"))?;
        selector_profiles.insert(id.to_owned(), serde_json::to_value(profile)?);
        expected.insert(path.clone(), ());
    }
    let referenced_profiles = source
        .inputs
        .values()
        .map(|input| input.selector.profile.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let exported_profiles = selector_profiles
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if referenced_profiles != exported_profiles {
        bail!("exported selector fragments must exactly cover the Source input bindings");
    }
    if artifacts.keys().any(|path| !expected.contains_key(path)) {
        bail!(
            "source export contains an artifact outside its current Source and pinned pack closure"
        );
    }

    let fragment = json!({"functions":[],"sourceId":source_id,"source":source_value});
    let mut normalized = BTreeMap::from([(
        format!("source-fragments/{source_id}.json"),
        serde_json::to_string_pretty(&fragment)?,
    )]);
    for (id, profile) in selector_profiles {
        normalized.insert(
            format!("selector-fragments/{id}.json"),
            serde_json::to_string_pretty(&profile)?,
        );
    }
    for path in expected.keys().filter(|path| path.starts_with(&pack_root)) {
        normalized.insert(path.clone(), artifacts[path].clone());
    }
    Ok(normalized)
}

fn fragment_value(
    path: &str,
    text: &str,
    format: &FormatSpec<'_>,
    document: &'static str,
) -> Result<Value, DocumentRefused> {
    let mut value = decode_authored::<Value>(path, text.as_bytes(), format)
        .map(|decoded| decoded.value)
        .map_err(|report| DocumentRefused { document, report })?;
    let object = value
        .as_object_mut()
        .expect("a document with an envelope is a mapping");
    object.remove("apiVersion");
    object.remove("kind");
    Ok(value)
}
