//! Label tables: `labels/<locale>.yaml`, one map of label keys to text that
//! every document declaring the locale receives.

use std::collections::BTreeMap;

use registry_platform_yaml::{
    local_id_collision_diagnostics, ApiVersion, AuthoredId, Diagnostic, DisplayText, Document,
    EnvelopeRule, Expect, FormatSpec, LocalId, Reader, Report,
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
    // The envelope, which the reader checks before decoding; declared so
    // the closed struct accepts it.
    #[allow(dead_code)]
    pub(crate) api_version: String,
    #[allow(dead_code)]
    pub(crate) kind: String,
    /// The text of each label, by key. Every locale of a document defines
    /// the same keys.
    pub(crate) labels: BTreeMap<LocalId, DisplayText>,
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
    read_labels_with_warning(file, bytes, None)
}

/// Include a bundle-context warning in the decoded table's one diagnostic budget.
pub(crate) fn read_labels_with_warning(
    file: &str,
    bytes: &[u8],
    warning: Option<Diagnostic>,
) -> Result<ReadLabels, Report> {
    let mut hook = registry_platform_config::AuthoredExpressions;
    let mut decoded = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<LabelsFile>(bytes, &Expect::one(&LABELS_FORMAT))
        .map_err(with_table_shape)?;
    if let Some(warning) = warning {
        decoded.document.push_warning(warning);
    }
    let label_ids = decoded
        .value
        .labels
        .keys()
        .map(|id| (id.as_str().to_owned(), format!("/labels/{id}")))
        .collect::<Vec<_>>();
    let authored_label_ids = label_ids
        .iter()
        .map(|(id, pointer)| AuthoredId::at_key(id, pointer))
        .collect::<Vec<_>>();
    let findings = decoded.document.report_with(local_id_collision_diagnostics(
        &decoded.document,
        "render.labels.label-id-collision",
        &authored_label_ids,
    ));
    if findings.has_errors() {
        return Err(findings);
    }
    let table = decoded
        .value
        .labels
        .into_iter()
        .map(|(key, text)| (key.into_string(), Value::String(text.into_string())))
        .collect::<serde_json::Map<_, _>>();
    Ok(ReadLabels {
        table: Value::Object(table),
        document: decoded.document,
    })
}

/// The shared reader's fix for a missing envelope names only the envelope;
/// a label table also needs its `labels:` mapping, so the fix names both.
fn with_table_shape(report: Report) -> Report {
    let files_checked = report.files_checked();
    let mut diagnostics = report.into_diagnostics();
    for diagnostic in &mut diagnostics {
        if diagnostic.code == "config.missing-envelope" {
            let fix = diagnostic.suggested_action.trim_end_matches('.');
            diagnostic.suggested_action =
                format!("{fix}, then write the label keys as a mapping under `labels:`.");
        }
    }
    let mut report = Report::new(diagnostics);
    if let Some(files) = files_checked {
        report.set_files_checked(files);
    }
    report
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
    fn label_collision_reports_are_bounded_per_file() {
        let mut text = format!("{HEAD}labels:\n");
        for index in 0..101 {
            text.push_str(&format!(
                "  label-{index}: First\n  label_{index}: Second\n"
            ));
        }
        let report = read_labels("labels/en.yaml", text.as_bytes()).unwrap_err();
        assert_eq!(report.files_checked(), Some(1));
        assert_eq!(report.diagnostics().len(), 101);
        assert_eq!(report.diagnostics()[0].path, "/labels/label_0");
        let marker = report.diagnostics().last().unwrap();
        assert_eq!(marker.code, "config.too-many-problems");
        assert_eq!(marker.severity, registry_platform_yaml::Severity::Error);
        assert_eq!(marker.message, "1 more problem in this file is not shown");
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
    fn a_table_without_its_envelope_is_told_the_whole_shape() {
        let report = read_labels("labels/en.yaml", b"title: Receipt\n").expect_err("refused");
        let diagnostic = &report.into_diagnostics()[0];
        assert_eq!(
            diagnostic.suggested_action,
            "Start the file with `apiVersion: id.registrystack.org/formats/render/labels/v1alpha1` \
             and `kind: RenderLabels`, then write the label keys as a mapping under `labels:`."
        );
    }

    #[test]
    fn keys_are_local_identifiers_and_values_are_display_text() {
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
        assert_eq!(
            codes(&format!("{HEAD}labels:\n  title: Receipt\u{202e}hidden\n")),
            [(
                "config.invalid-value".to_owned(),
                "/labels/title".to_owned()
            )]
        );
    }

    #[test]
    fn cfg_val_11_refused_display_text_is_located_without_repeating_it() {
        let text = format!("{HEAD}labels:\n  title: Receipt\u{202e}hidden\n");
        let report = read_labels("labels/ar.yaml", text.as_bytes()).expect_err("refused");
        let diagnostic = &report.diagnostics()[0];
        let source = diagnostic.source.as_ref().expect("source position");
        assert_eq!(diagnostic.code, "config.invalid-value");
        assert_eq!(diagnostic.path, "/labels/title");
        assert_eq!(source.file, "labels/ar.yaml");
        assert_eq!((source.line, source.column), (Some(4), Some(10)));
        assert!(!diagnostic.message.contains("hidden"));
    }

    #[test]
    fn cfg_id_8_separator_colliding_label_ids_point_to_both_keys() {
        let text = format!("{HEAD}labels:\n  receipt-copy: Original\n  receipt_copy: Duplicate\n");
        let report = read_labels("labels/en.yaml", text.as_bytes()).expect_err("refused");
        let diagnostic = &report.diagnostics()[0];
        let source = diagnostic.source.as_ref().expect("primary source position");
        assert_eq!(diagnostic.code, "render.labels.label-id-collision");
        assert_eq!(diagnostic.path, "/labels/receipt_copy");
        assert_eq!(source.file, "labels/en.yaml");
        assert_eq!((source.line, source.column), (Some(5), Some(3)));
        assert_eq!(diagnostic.related.len(), 1);
        assert_eq!(diagnostic.related[0].path, "/labels/receipt-copy");
        assert_eq!(diagnostic.related[0].file, "labels/en.yaml");
        assert_eq!(
            (diagnostic.related[0].line, diagnostic.related[0].column),
            (Some(4), Some(3))
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
