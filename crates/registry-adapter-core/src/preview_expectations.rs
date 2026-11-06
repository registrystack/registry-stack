// SPDX-License-Identifier: Apache-2.0

//! The `AdapterPreviewExpectations` authoring model: the result each preview
//! sample of a mapping is meant to give, kept in `expected.yaml` beside the
//! samples (`products/adapter/VISUAL-MAPPING.md`).
//!
//! A refused sample is a deliberate input, so the file says which samples
//! the mapping accepts and which it refuses, and optionally the target a
//! refusal names. A sample the file does not list has no expectation. The
//! model and its checks are pure: the caller supplies the sample names and the
//! targets the mapping reads.

use std::collections::BTreeMap;

use registry_platform_yaml::{Diagnostic, ExternalId};
use serde::{Deserialize, Serialize};

use crate::mapping::{canonical_target_path, MappingCode};
use crate::naming::{ADAPTER_PREVIEW_EXPECTATIONS_API_VERSION, ADAPTER_PREVIEW_EXPECTATIONS_KIND};

/// The authored preview expectations.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterPreviewExpectations {
    /// The format envelope version.
    pub api_version: String,
    /// The format kind: `AdapterPreviewExpectations`.
    pub kind: String,
    /// The expected result of each sample, keyed by the sample's file name
    /// without its extension.
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::model::external_id_map_schema::<SampleExpectation>")
    )]
    pub samples: BTreeMap<ExternalId, SampleExpectation>,
}

impl AdapterPreviewExpectations {
    /// Whether the envelope members carry this format's fixed names.
    #[must_use]
    pub fn has_current_envelope(&self) -> bool {
        self.api_version == ADAPTER_PREVIEW_EXPECTATIONS_API_VERSION
            && self.kind == ADAPTER_PREVIEW_EXPECTATIONS_KIND
    }
}

/// What one sample is meant to give.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SampleExpectation {
    /// The mapping accepts the sample.
    Accepted {},
    /// The mapping refuses the sample. With a `target`, a refusal must name
    /// that target field, in the mapping's target syntax; without one, any
    /// refusal of the mapping will do.
    Refused {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<ExternalId>,
    },
}

registry_platform_yaml::tagged_union!(SampleExpectation, tag = "type");
crate::model::serialize_tagged_union!(SampleExpectation, tag = "type");

/// Whether a refusal that names `refused` is a refusal at `expected`: both
/// are read in the mapping's target syntax, so `"a"` and `a` are one target.
/// Text outside the syntax names only itself.
#[must_use]
pub fn refusal_names_target(expected: &str, refused: &str) -> bool {
    match (
        canonical_target_path(expected),
        canonical_target_path(refused),
    ) {
        (Some(expected), Some(refused)) => expected == refused,
        _ => false,
    }
}

fn finding(code: MappingCode, path: String, message: String, action: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(code.code(), path, message, action);
    diagnostic.artifact = Some(ADAPTER_PREVIEW_EXPECTATIONS_KIND.to_string());
    diagnostic
}

/// Check the expectations against the samples that sit beside them and the
/// targets the mapping reads from its source. A name with no sample is
/// refused; a sample the file does not list has no expectation, and is not an
/// error. A refusal that names a target no assignment reads from the source
/// could never match, so it is refused too. Diagnostics name the position,
/// never the text.
#[must_use]
pub fn check_preview_expectations(
    expectations: &AdapterPreviewExpectations,
    sample_names: &[String],
    read_targets: &[String],
) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for (name, expectation) in &expectations.samples {
        if !sample_names.iter().any(|sample| sample == name.as_str()) {
            findings.push(finding(
                MappingCode::ExpectationSampleUnknown,
                format!("/samples/{}", pointer_token(name.as_str())),
                "the expectation names a sample that has no file beside the expectations"
                    .to_string(),
                "Add the sample file, or remove the expectation. A sample is named by its file name without the extension.",
            ));
        }
        if let SampleExpectation::Refused {
            target: Some(target),
        } = expectation
        {
            if !read_targets
                .iter()
                .any(|read| refusal_names_target(target.as_str(), read))
            {
                findings.push(finding(
                    MappingCode::ExpectationTargetUnknown,
                    format!("/samples/{}/target", pointer_token(name.as_str())),
                    "the refusal names a target that no assignment reads from the source"
                        .to_string(),
                    "Name the target of an assignment that has a `from`, or expect `refused` alone.",
                ));
            }
        }
    }
    findings
}

/// A JSON Pointer reference token for `name`.
fn pointer_token(name: &str) -> String {
    name.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(text: &str) -> ExternalId {
        ExternalId::new(text).unwrap()
    }

    fn parse(value: serde_json::Value) -> Result<AdapterPreviewExpectations, serde_json::Error> {
        serde_json::from_value(value)
    }

    fn expectations(samples: serde_json::Value) -> AdapterPreviewExpectations {
        parse(json!({
            "apiVersion": ADAPTER_PREVIEW_EXPECTATIONS_API_VERSION,
            "kind": ADAPTER_PREVIEW_EXPECTATIONS_KIND,
            "samples": samples,
        }))
        .expect("valid expectations")
    }

    #[test]
    fn a_sample_is_accepted_refused_or_refused_at_a_target() {
        let parsed = expectations(json!({
            "good": {"type": "accepted"},
            "bad": {"type": "refused"},
            "missing": {"type": "refused", "target": "respondentName"},
        }));
        assert!(parsed.has_current_envelope());
        assert_eq!(parsed.samples[&key("good")], SampleExpectation::Accepted {});
        assert_eq!(
            parsed.samples[&key("bad")],
            SampleExpectation::Refused { target: None }
        );
        assert_eq!(
            parsed.samples[&key("missing")],
            SampleExpectation::Refused {
                target: Some(key("respondentName"))
            }
        );
    }

    #[test]
    fn an_expectation_round_trips() {
        let parsed = expectations(json!({
            "good": {"type": "accepted"},
            "bad": {"type": "refused"},
            "missing": {"type": "refused", "target": "respondentName"},
        }));
        let value = serde_json::to_value(&parsed).unwrap();
        assert_eq!(value["samples"]["good"], json!({"type": "accepted"}));
        assert_eq!(value["samples"]["bad"], json!({"type": "refused"}));
        assert_eq!(
            value["samples"]["missing"],
            json!({"type": "refused", "target": "respondentName"})
        );
        assert_eq!(parse(value).unwrap(), parsed);
    }

    #[test]
    fn anything_else_is_refused() {
        for bad in [
            json!("accepted"),
            json!(true),
            json!(3),
            json!(null),
            json!([]),
            json!({}),
            json!({"type": "rejected"}),
            json!({"type": "Accepted"}),
            json!({"type": "accepted", "target": "x"}),
            json!({"type": "refused", "target": ""}),
            json!({"type": "refused", "target": 7}),
            json!({"type": "refused", "extra": "b"}),
            json!({"refused": "a"}),
        ] {
            let result = parse(json!({
                "apiVersion": ADAPTER_PREVIEW_EXPECTATIONS_API_VERSION,
                "kind": ADAPTER_PREVIEW_EXPECTATIONS_KIND,
                "samples": {"s": bad.clone()},
            }));
            assert!(result.is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn the_file_is_closed() {
        assert!(parse(json!({
            "apiVersion": ADAPTER_PREVIEW_EXPECTATIONS_API_VERSION,
            "kind": ADAPTER_PREVIEW_EXPECTATIONS_KIND,
            "samples": {},
            "extra": 1,
        }))
        .is_err());
        assert!(parse(json!({
            "apiVersion": ADAPTER_PREVIEW_EXPECTATIONS_API_VERSION,
            "kind": ADAPTER_PREVIEW_EXPECTATIONS_KIND,
        }))
        .is_err());
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn a_name_with_no_sample_file_is_refused() {
        let parsed = expectations(json!({
            "good": {"type": "accepted"},
            "gone": {"type": "refused"},
        }));
        let findings = check_preview_expectations(&parsed, &names(&["good", "other"]), &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(
            findings[0].code,
            "adapter.mapping.expectation-sample-unknown"
        );
        assert_eq!(findings[0].path, "/samples/gone");
        assert!(!findings[0].suggested_action.is_empty());
    }

    #[test]
    fn a_sample_the_file_does_not_list_is_not_an_error() {
        let parsed = expectations(json!({"good": {"type": "accepted"}}));
        assert_eq!(
            check_preview_expectations(&parsed, &names(&["good", "unlisted"]), &[]),
            vec![]
        );
    }

    #[test]
    fn a_refusal_must_name_a_target_the_mapping_reads() {
        let parsed = expectations(json!({
            "a": {"type": "refused", "target": "respondentName"},
            "b": {"type": "refused", "target": "nowhere"},
            "c": {"type": "refused"},
        }));
        let targets = names(&["respondentName", "householdSize"]);
        let findings = check_preview_expectations(&parsed, &names(&["a", "b", "c"]), &targets);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(
            findings[0].code,
            "adapter.mapping.expectation-target-unknown"
        );
        assert_eq!(findings[0].path, "/samples/b/target");
        assert!(!findings[0].message.contains("nowhere"), "{findings:?}");
    }

    #[test]
    fn a_target_is_compared_in_the_formats_canonical_form() {
        let parsed =
            expectations(json!({"a": {"type": "refused", "target": "\"household.size\""}}));
        let targets = names(&["\"household.size\""]);
        assert_eq!(
            check_preview_expectations(&parsed, &names(&["a"]), &targets),
            vec![]
        );
        let parsed = expectations(json!({"a": {"type": "refused", "target": "a..b"}}));
        let findings = check_preview_expectations(&parsed, &names(&["a"]), &targets);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].code,
            "adapter.mapping.expectation-target-unknown"
        );
    }

    #[test]
    fn a_refusal_names_the_same_target_however_it_is_written() {
        assert!(refusal_names_target("household.size", "household.size"));
        assert!(refusal_names_target("\"a\"", "a"));
        assert!(refusal_names_target("a", "\"a\""));
        assert!(!refusal_names_target("a", "b"));
        assert!(!refusal_names_target("a..b", "b"));
    }
}
