//! The source resolution file named by `--resolutions`, read through the
//! shared configuration reader.

use std::{collections::BTreeMap, path::PathBuf};

use registry_platform_yaml::{
    tagged_union, ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader, RemovedKey,
};
use serde::Deserialize;

use super::DocumentRefused;

/// The `apiVersion` of a source resolution file.
pub(crate) const RESOLUTION_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/source-resolution/v1alpha1";
/// The `kind` of a source resolution file.
pub(crate) const RESOLUTION_KIND: &str = "EvidenceSourceResolution";
/// The published `$id` of the source resolution file's JSON Schema.
#[cfg(feature = "schema")]
pub(crate) const RESOLUTION_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/source-resolution/source-resolution.v1alpha1.schema.json";
/// The most artifacts one resolution file may decide.
pub(super) const MAX_ARTIFACTS: usize = 256;

pub(crate) const RESOLUTION_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: RESOLUTION_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(RESOLUTION_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[RemovedKey {
        pointer: "/formatVersion",
        replacement: "Delete `formatVersion`; `apiVersion` replaces it.",
    }],
};

/// What to do with one artifact the three-way comparison could not decide.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub(crate) enum Resolution {
    Keep {},
    Adopt {},
    File { path: PathBuf },
}
tagged_union!(Resolution, tag = "type");

/// The resolution file as written. The reader checks and strips its
/// `apiVersion` and `kind`.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResolutionFile {
    #[cfg_attr(feature = "schema", schemars(schema_with = "artifacts_schema"))]
    pub(super) artifacts: BTreeMap<String, Resolution>,
}

/// The closed shape of the artifact decisions: each artifact path maps to one
/// resolution.
#[cfg(feature = "schema")]
fn artifacts_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let paths = generator.subschema_for::<registry_platform_yaml::ExternalId>();
    let resolution = generator.subschema_for::<Resolution>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": paths,
        "maxProperties": MAX_ARTIFACTS,
        "additionalProperties": resolution
    })
}

/// Decode `bytes`, the resolution file at `file`, refusing it with the
/// reader's diagnostics.
pub(crate) fn decode_resolution_file(
    file: &str,
    bytes: &[u8],
) -> Result<ResolutionFile, DocumentRefused> {
    Reader::new(file)
        .decode::<ResolutionFile>(bytes, &Expect::one(&RESOLUTION_FORMAT))
        .map(|decoded| decoded.value)
        .map_err(|report| DocumentRefused {
            document: "source resolution file",
            report,
        })
}

/// The derived JSON Schema of one resolution file.
#[cfg(feature = "schema")]
pub(crate) fn resolution_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(ResolutionFile)).expect("a derived schema is JSON")
}
