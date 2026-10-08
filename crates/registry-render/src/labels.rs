//! Label tables: `labels/<locale>.yaml`, one map of label keys to text that
//! every document declaring the locale receives.

use std::collections::BTreeMap;

use registry_platform_yaml::{
    ApiVersion, Document, EnvelopeRule, Expect, FormatSpec, LocalId, Reader, Report,
};
use serde::Deserialize;
use serde_json::Value;

pub const LABELS_API_VERSION: &str = "id.registrystack.org/formats/render/labels/v1alpha1";
pub const LABELS_KIND: &str = "RenderLabels";
/// The directory, inside a bundle, that holds the label tables.
pub const LABELS_DIRECTORY: &str = "labels";

/// A label table as the shared reader accepts it.
pub(crate) const LABELS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: LABELS_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(LABELS_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// `labels/<locale>.yaml`: the text a template prints, by label key.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct LabelsFile {
    /// The envelope, which the reader checks before decoding; declared so
    /// the closed struct accepts it.
    #[allow(dead_code)]
    pub(crate) api_version: String,
    #[allow(dead_code)]
    pub(crate) kind: String,
    /// The text of each label, by key. Every locale of a document defines
    /// the same keys.
    pub(crate) labels: BTreeMap<LocalId, String>,
}

/// A label table the reader accepted: the flat key-to-text map the template
/// receives, with the document its findings are placed in.
#[derive(Debug, Clone)]
pub(crate) struct ReadLabels {
    pub(crate) table: Value,
    pub(crate) document: Document,
}

/// The bundle path of the label table for `locale`.
pub(crate) fn labels_path(locale: &str) -> String {
    format!("{LABELS_DIRECTORY}/{locale}.yaml")
}

/// Read one label table through the shared reader, refusing every `${...}`
/// expression (CFG-SEC-2). `file` is the name every diagnostic carries.
pub(crate) fn read_labels(file: &str, bytes: &[u8]) -> Result<ReadLabels, Report> {
    let mut hook = registry_platform_config::AuthoredExpressions;
    let decoded = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<LabelsFile>(bytes, &Expect::one(&LABELS_FORMAT))?;
    let table = decoded
        .value
        .labels
        .into_iter()
        .map(|(key, text)| (key.into_string(), Value::String(text)))
        .collect::<serde_json::Map<_, _>>();
    Ok(ReadLabels {
        table: Value::Object(table),
        document: decoded.document,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str =
        "apiVersion: id.registrystack.org/formats/render/labels/v1alpha1\nkind: RenderLabels\n";

    fn codes(text: &str) -> Vec<(String, String)> {
        read_labels("labels/en.yaml", text.as_bytes())
            .expect_err("refused")
            .into_diagnostics()
            .into_iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.path))
            .collect()
    }

    #[test]
    fn a_label_table_is_the_flat_map_the_template_receives() {
        let read = read_labels(
            "labels/en.yaml",
            format!("{HEAD}labels:\n  title: Receipt\n  call-center: Call us\n").as_bytes(),
        )
        .unwrap();
        assert_eq!(
            read.table,
            serde_json::json!({"title": "Receipt", "call-center": "Call us"})
        );
    }

    #[test]
    fn cfg_env_1_a_table_without_its_envelope_is_refused() {
        assert_eq!(
            codes("title: Receipt\n"),
            [("config.missing-envelope".to_owned(), String::new())]
        );
    }

    #[test]
    fn keys_are_local_identifiers_and_values_are_text() {
        assert_eq!(
            codes(&format!("{HEAD}labels:\n  Title: Receipt\n")),
            [(
                "config.invalid-value".to_owned(),
                "/labels/Title".to_owned()
            )]
        );
        assert_eq!(
            codes(&format!("{HEAD}labels:\n  count: 3\n")),
            [(
                "config.expected-string".to_owned(),
                "/labels/count".to_owned()
            )]
        );
    }

    #[test]
    fn cfg_sec_2_a_label_carrying_an_environment_expression_is_refused() {
        assert_eq!(
            codes(&format!("{HEAD}labels:\n  title: ${{TITLE}}\n")),
            [(
                "config.substitution-not-allowed".to_owned(),
                "/labels/title".to_owned()
            )]
        );
    }
}
