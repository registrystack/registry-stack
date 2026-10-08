// SPDX-License-Identifier: Apache-2.0
//! The selection document: which concepts of a reference model become
//! entities, and which of their properties become fields.
//!
//! A selection is the whole input of a model-driven `init`. The wizard writes
//! one, a starter ships one, and `--selection` reads one, so the three ways of
//! running the command converge on the same document before anything is
//! generated. The document is echoed into the written project, which is how a
//! reader reproduces or amends a project later.

use std::fmt;

use registry_platform_yaml::{
    ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader, Report, RetiredApiVersion,
};
use serde::{Deserialize, Serialize};

/// The document's `apiVersion`.
pub(crate) const API_VERSION: &str = "id.registrystack.org/formats/breg/model-selection/v1alpha1";
/// The document's `kind`.
pub(crate) const KIND: &str = "BRegModelSelection";
/// The selection format and the header it retired.
pub(crate) const SELECTION_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[RetiredApiVersion {
            api_version: "registry.registrystack.org/breg-model-selection/v1alpha1",
            replacement: "Write `apiVersion: id.registrystack.org/formats/breg/model-selection/v1alpha1` and `kind: BRegModelSelection`; the members are unchanged.",
        }],
    },
    removed_keys: &[],
};

/// A reference model the command can derive a project from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ModelName {
    /// The PublicSchema reference model embedded in this binary.
    Publicschema,
}

impl fmt::Display for ModelName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Publicschema => formatter.write_str("publicschema"),
        }
    }
}

/// What a model-driven `init` generates from. The shared reader checks and
/// removes the header before the members are decoded, so the header members
/// are written from the format and never read.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Selection {
    #[serde(skip_deserializing, default = "api_version")]
    pub api_version: String,
    #[serde(skip_deserializing, default = "kind")]
    pub kind: String,
    pub model: ModelName,
    /// The model version the selection was written against. When present it
    /// must equal the embedded snapshot's declared version label. Several
    /// revisions of the model can share one version label, so this alone does
    /// not pin a revision; `modelRevision` does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    /// The upstream commit of the model snapshot the selection was written
    /// against. When present it must equal the embedded snapshot's commit, so
    /// a selection written for one revision of the model is not silently
    /// applied to another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_revision: Option<String>,
    pub registry: RegistrySelection,
    pub entities: Vec<EntitySelection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vocabularies: Vec<VocabularySelection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RegistrySelection {
    pub id: String,
    pub title: String,
}

/// One concept of the model that becomes an entity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct EntitySelection {
    /// The concept's name in the model.
    pub concept: String,
    /// The entity identifier; the concept name in kebab case when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The collection route; the entity identifier pluralized when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    /// The field that identifies a record; `<id>-code` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier_field: Option<String>,
    /// The entity classification; `internal` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<PropertySelection>,
}

/// One property of the concept that becomes a field.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct PropertySelection {
    /// The property's name in the model.
    pub name: String,
    /// For a property whose range is another concept: the selected entity the
    /// reference points at. Required only when more than one selected entity
    /// fits the range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// How one enumeration of the model is carried, overriding the size rule.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct VocabularySelection {
    /// The enumeration's name in the model.
    pub r#enum: String,
    pub mode: VocabularyMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum VocabularyMode {
    /// A closed `vocabulary-code` field with every value listed in the
    /// project.
    Inline,
    /// A bounded string that carries the code without the project listing the
    /// values.
    Code,
}

impl Selection {
    /// Reads a selection document through the shared reader, refusing any
    /// other document kind. `source` names the document in the diagnostics.
    pub(crate) fn parse(source: &str, bytes: &[u8]) -> Result<Self, Report> {
        Reader::new(source)
            .decode::<Self>(bytes, &Expect::one(&SELECTION_FORMAT))
            .map(|decoded| decoded.value)
    }

    /// The document as YAML, for the echo written into the project.
    pub(crate) fn to_yaml(&self) -> String {
        serde_norway::to_string(self).expect("a selection serializes")
    }
}

fn api_version() -> String {
    API_VERSION.to_owned()
}

fn kind() -> String {
    KIND.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
apiVersion: id.registrystack.org/formats/breg/model-selection/v1alpha1
kind: BRegModelSelection
model: publicschema
registry:
  id: example
  title: Example
entities:
  - concept: Thing
    properties:
      - name: label
"#;

    /// The header an earlier `bregctl` wrote.
    const RETIRED_API_VERSION: &str = "registry.registrystack.org/breg-model-selection/v1alpha1";

    fn codes(report: &Report) -> Vec<&str> {
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect()
    }

    #[test]
    fn a_minimal_document_parses_with_defaults() {
        let selection = Selection::parse("test", MINIMAL.as_bytes()).expect("parses");
        assert_eq!(selection.api_version, API_VERSION);
        assert_eq!(selection.kind, KIND);
        assert_eq!(selection.model, ModelName::Publicschema);
        assert_eq!(selection.model_version, None);
        assert_eq!(selection.model_revision, None);
        assert_eq!(selection.entities.len(), 1);
        assert_eq!(selection.entities[0].concept, "Thing");
        assert_eq!(selection.entities[0].id, None);
        assert_eq!(selection.entities[0].properties[0].name, "label");
        assert!(selection.vocabularies.is_empty());
    }

    #[test]
    fn the_echo_round_trips() {
        let selection = Selection::parse("test", MINIMAL.as_bytes()).expect("parses");
        let echo = selection.to_yaml();
        assert!(
            echo.starts_with(&format!("apiVersion: {API_VERSION}\nkind: {KIND}\n")),
            "{echo}"
        );
        let echoed = Selection::parse("echo", echo.as_bytes()).expect("parses");
        assert_eq!(echoed, selection);
    }

    #[test]
    fn another_kind_is_refused_by_name() {
        let document = MINIMAL.replace("kind: BRegModelSelection", "kind: RegistryProject");
        let report = Selection::parse("test", document.as_bytes()).expect_err("refused");
        assert_eq!(codes(&report), ["config.wrong-kind"]);
        let diagnostic = &report.diagnostics()[0];
        assert!(diagnostic.message.contains(KIND), "{}", diagnostic.message);
        let source = diagnostic.source.as_ref().expect("positioned");
        assert_eq!((source.file.as_str(), source.line), ("test", Some(3)));
    }

    #[test]
    fn the_header_an_earlier_bregctl_wrote_is_refused_naming_the_current_one() {
        let document = MINIMAL.replace(API_VERSION, RETIRED_API_VERSION);
        let report = Selection::parse("test", document.as_bytes()).expect_err("refused");
        assert_eq!(codes(&report), ["config.retired-api-version"]);
        let diagnostic = &report.diagnostics()[0];
        assert!(
            diagnostic.suggested_action.contains(API_VERSION)
                && diagnostic.suggested_action.contains(KIND),
            "{}",
            diagnostic.suggested_action
        );
        let document = document.replace("kind: BRegModelSelection", "kind: ModelSelection");
        let report = Selection::parse("test", document.as_bytes()).expect_err("refused");
        assert_eq!(codes(&report), ["config.wrong-kind"]);
    }

    #[test]
    fn every_unknown_key_is_refused_at_its_position() {
        let document = format!("{MINIMAL}  - concept: Other\n    colour: blue\n    shade: dark\n");
        let report = Selection::parse("test", document.as_bytes()).expect_err("refused");
        assert_eq!(codes(&report), ["config.unknown-key", "config.unknown-key"]);
        let places: Vec<(&str, Option<usize>)> = report
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                let source = diagnostic.source.as_ref().expect("positioned");
                (diagnostic.path.as_str(), source.line)
            })
            .collect();
        assert_eq!(
            places,
            [
                ("/entities/1/colour", Some(13)),
                ("/entities/1/shade", Some(14))
            ]
        );
    }

    #[test]
    fn an_empty_document_is_refused() {
        let report = Selection::parse("test", b"").expect_err("refused");
        assert_eq!(codes(&report), ["config.missing-envelope"]);
    }
}
