// SPDX-License-Identifier: Apache-2.0
//! Reads a test manifest written as YAML.
//!
//! The text is read by the shared Registry Stack reader into a JSON value,
//! and `MetadataManifest` is deserialized from that value, so a test sees
//! the library's own refusals and their messages.

use registry_manifest_core::MetadataManifest;
use registry_platform_yaml::{EnvelopeRule, Expect, FormatSpec, Reader};

const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: "ManifestMetadata",
    envelope: EnvelopeRule::Exempt {
        reason: "a metadata manifest names its version in schema_version",
    },
    removed_keys: &[],
};

/// Deserialize a metadata manifest from YAML text. Panics when the text is
/// not YAML the shared reader reads; returns the library's refusal otherwise.
pub fn from_yaml(raw: &str) -> Result<MetadataManifest, serde_json::Error> {
    let value = Reader::new("metadata.yaml")
        .decode::<serde_json::Value>(raw.as_bytes(), &Expect::one(&FORMAT))
        .unwrap_or_else(|report| {
            panic!(
                "the test manifest is not YAML the shared reader reads:\n{}",
                report.render_human()
            )
        })
        .value;
    serde_json::from_value(value)
}
