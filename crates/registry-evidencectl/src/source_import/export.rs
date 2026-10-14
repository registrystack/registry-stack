//! The export manifest, `source-export.json`, read through the shared
//! configuration reader.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context as _, Result};
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

/// Translate the public BReg source-export vocabulary into one normalized
/// EvidenceProject fragment plus named Function assets. The export remains a
/// technical source contract: it contributes no AssertionDefinition or grant.
pub(super) fn normalize_artifacts(
    source_id: &str,
    artifacts: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let source_path = format!("sources/{source_id}.yaml");
    let mut source = yaml_value(
        &source_path,
        artifacts
            .get(&source_path)
            .ok_or_else(|| anyhow!("source export is missing {source_path}"))?,
    )?;
    let source_object = source
        .as_object_mut()
        .ok_or_else(|| anyhow!("exported Source must be a mapping"))?;
    if source_object.contains_key("adapterParameters") {
        bail!("exported Source requires adapterParameters inside request");
    }
    source_object.remove("apiVersion");
    source_object.remove("kind");
    let posture = source_object
        .remove("posture")
        .ok_or_else(|| anyhow!("exported Source requires posture"))?;
    source_object.insert("acquisitionPosture".to_owned(), posture);
    source_object.remove("authentication");
    source_object.remove("baseUrl");

    let request = source_object
        .get_mut("request")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("exported Source requires a request mapping"))?;
    let selector_inputs = request
        .remove("selectorInputs")
        .unwrap_or_else(|| json!([]));
    let projection = request.remove("projection").unwrap_or_else(|| json!([]));
    let prepare_script = request
        .remove("prepareScript")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| anyhow!("exported Source requires prepareScript"))?;
    let adapter_schema_path = request
        .remove("adapterParametersSchema")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| anyhow!("exported Source requires adapterParametersSchema"))?;
    let adapter_parameters = request.remove("adapterParameters");
    let redirects = request
        .remove("redirects")
        .ok_or_else(|| anyhow!("exported Source requires redirects"))?;
    if redirects.as_str() != Some("deny") {
        bail!("exported Source requires redirects to be `deny`");
    }
    let timeout = request
        .remove("attemptTimeoutMilliseconds")
        .unwrap_or_else(|| json!(5000));
    let maximum_bytes = request
        .remove("maximumResponseBytes")
        .unwrap_or_else(|| json!(65536));
    request.remove("maximumConcurrency");
    let preparation_limits = request.remove("preparationLimits");

    let response_schema_path = source_object
        .remove("responseSchema")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| anyhow!("exported Source requires responseSchema"))?;
    let extract_script = source_object
        .remove("extractScript")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| anyhow!("exported Source requires extractScript"))?;
    let facts_schema_path = source_object
        .remove("factSchema")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| anyhow!("exported Source requires factSchema"))?;
    let response_shape = yaml_value(
        &response_schema_path,
        artifacts
            .get(&response_schema_path)
            .ok_or_else(|| anyhow!("source export is missing {response_schema_path}"))?,
    )?;
    let facts_schema = yaml_value(
        &facts_schema_path,
        artifacts
            .get(&facts_schema_path)
            .ok_or_else(|| anyhow!("source export is missing {facts_schema_path}"))?,
    )?;
    let facts = facts_schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| anyhow!("exported fact schema requires properties"))?;
    let adapter_parameters_schema = yaml_value(
        &adapter_schema_path,
        artifacts
            .get(&adapter_schema_path)
            .ok_or_else(|| anyhow!("source export is missing {adapter_schema_path}"))?,
    )?;

    let selectors = selector_inputs
        .as_array()
        .into_iter()
        .flatten()
        .map(|input| {
            let role = input
                .get("role")
                .cloned()
                .ok_or_else(|| anyhow!("exported selector input requires role"))?;
            let profiles = input
                .get("alternatives")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|alternative| alternative.get("profile").cloned())
                .collect::<Vec<_>>();
            Ok(json!({"role":role,"profiles":profiles}))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut selector_profiles = BTreeMap::new();
    for path in artifacts
        .keys()
        .filter(|path| path.starts_with("selectors/") && path.ends_with(".yaml"))
    {
        let id = path
            .trim_start_matches("selectors/")
            .trim_end_matches(".yaml");
        let mut profile = yaml_value(path, &artifacts[path])?;
        let object = profile
            .as_object_mut()
            .ok_or_else(|| anyhow!("exported SelectorProfile must be a mapping"))?;
        object.remove("apiVersion");
        object.remove("kind");
        let profile =
            serde_json::from_value::<registry_evidence_authoring::project::SelectorProfile>(
                profile,
            )
            .with_context(|| format!("{path} does not fit EvidenceProject"))?;
        selector_profiles.insert(id.to_owned(), serde_json::to_value(profile)?);
    }

    let prepare_id = format!("{source_id}-prepare");
    let extract_id = format!("{source_id}-extract");
    source_object.insert("selectors".to_owned(), Value::Array(selectors));
    source_object.insert(
        "response".to_owned(),
        json!({"projection":projection,"shape":response_shape,"maximumBytes":maximum_bytes}),
    );
    source_object.insert("prepare".to_owned(), json!({"function":prepare_id}));
    source_object.insert("extract".to_owned(), json!({"function":extract_id}));
    source_object.insert("facts".to_owned(), Value::Object(facts));
    source_object.insert(
        "limits".to_owned(),
        json!({"attemptTimeoutMilliseconds":timeout,"maximumConcurrency":8}),
    );
    source_object.insert(
        "adapterParametersSchema".to_owned(),
        adapter_parameters_schema,
    );
    if let Some(parameters) = adapter_parameters {
        source_object.insert("adapterParameters".to_owned(), parameters);
    }
    if let Some(limits) = preparation_limits {
        source_object.insert("preparationLimits".to_owned(), limits);
    }
    let source = serde_json::to_value(
        serde_json::from_value::<registry_evidence_authoring::project::Source>(source)
            .context("the exported Source does not fit EvidenceProject")?,
    )?;

    let mut functions = vec![
        json!({"id":prepare_id,"interface":"source-prepare/v1","source":format!("functions/{source_id}-prepare.rhai")}),
        json!({"id":extract_id,"interface":"source-extract/v1","source":format!("functions/{source_id}-extract.rhai")}),
    ];
    let mut extra_functions = BTreeMap::new();
    for (path, text) in artifacts.iter().filter(|(path, _)| {
        path.starts_with("adapters/")
            && path.ends_with(".rhai")
            && path.as_str() != prepare_script
            && path.as_str() != extract_script
    }) {
        let id = path
            .trim_start_matches("adapters/")
            .trim_end_matches(".rhai");
        functions.push(json!({"id":id,"interface":"source-extract/v1","source":format!("functions/{id}.rhai")}));
        extra_functions.insert(format!("functions/{id}.rhai"), text.clone());
    }
    let fragment = json!({"functions":functions,"sourceId":source_id,"source":source});
    let prepare = artifacts
        .get(&prepare_script)
        .ok_or_else(|| anyhow!("source export is missing {prepare_script}"))?;
    let extract = artifacts
        .get(&extract_script)
        .ok_or_else(|| anyhow!("source export is missing {extract_script}"))?;
    let mut normalized = BTreeMap::from([
        (
            format!("source-fragments/{source_id}.json"),
            serde_json::to_string_pretty(&fragment)?,
        ),
        (
            format!("functions/{source_id}-prepare.rhai"),
            prepare.clone(),
        ),
        (
            format!("functions/{source_id}-extract.rhai"),
            extract.clone(),
        ),
    ]);
    for (id, profile) in selector_profiles {
        normalized.insert(
            format!("selector-fragments/{id}.json"),
            serde_json::to_string_pretty(&profile)?,
        );
    }
    normalized.extend(extra_functions);
    Ok(normalized)
}

fn yaml_value(path: &str, text: &str) -> Result<Value> {
    match Reader::new(path).scan(text.as_bytes()) {
        Ok(Some(node)) => Ok(node.to_json_value()),
        Ok(None) => bail!("{path} is empty"),
        Err(report) => bail!("{path} was refused:\n{}", report.render_human()),
    }
}
