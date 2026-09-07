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

use serde::{Deserialize, Serialize};

use registry_breg::Diagnostic;

use crate::diagnostic;

/// The document's `apiVersion`.
pub(crate) const API_VERSION: &str = "registry.registrystack.org/breg-model-selection/v1alpha1";
/// The document's `kind`.
pub(crate) const KIND: &str = "ModelSelection";

/// The largest selection document the command reads.
const MAX_SELECTION_BYTES: usize = 256 * 1024;

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

/// What a model-driven `init` generates from.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Selection {
    pub api_version: String,
    pub kind: String,
    pub model: ModelName,
    /// The model version the selection was written against. When present it
    /// must equal the embedded snapshot's version, so a selection written for
    /// one revision of the model is not silently applied to another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
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
    /// Parses a selection document, refusing any other document kind.
    pub(crate) fn parse(source: &str, bytes: &[u8]) -> Result<Self, Diagnostic> {
        if bytes.is_empty() || bytes.len() > MAX_SELECTION_BYTES {
            return Err(diagnostic(
                "init.selection.size",
                source,
                &format!("a selection document must be between 1 and {MAX_SELECTION_BYTES} bytes"),
            ));
        }
        let selection: Self = serde_norway::from_slice(bytes).map_err(|error| {
            diagnostic(
                "init.selection.invalid",
                source,
                &format!("the selection document does not parse: {error}"),
            )
        })?;
        if selection.api_version != API_VERSION || selection.kind != KIND {
            return Err(diagnostic(
                "init.selection.kind",
                source,
                &format!(
                    "a selection document declares apiVersion `{API_VERSION}` and kind `{KIND}`"
                ),
            ));
        }
        Ok(selection)
    }

    /// The document as YAML, for the echo written into the project.
    pub(crate) fn to_yaml(&self) -> String {
        serde_norway::to_string(self).expect("a selection serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
apiVersion: registry.registrystack.org/breg-model-selection/v1alpha1
kind: ModelSelection
model: publicschema
registry:
  id: example
  title: Example
entities:
  - concept: Thing
    properties:
      - name: label
"#;

    #[test]
    fn a_minimal_document_parses_with_defaults() {
        let selection = Selection::parse("test", MINIMAL.as_bytes()).expect("parses");
        assert_eq!(selection.model, ModelName::Publicschema);
        assert_eq!(selection.model_version, None);
        assert_eq!(selection.entities.len(), 1);
        assert_eq!(selection.entities[0].concept, "Thing");
        assert_eq!(selection.entities[0].id, None);
        assert_eq!(selection.entities[0].properties[0].name, "label");
        assert!(selection.vocabularies.is_empty());
    }

    #[test]
    fn the_echo_round_trips() {
        let selection = Selection::parse("test", MINIMAL.as_bytes()).expect("parses");
        let echoed = Selection::parse("echo", selection.to_yaml().as_bytes()).expect("parses");
        assert_eq!(echoed, selection);
    }

    #[test]
    fn another_kind_is_refused_by_name() {
        let document = MINIMAL.replace("kind: ModelSelection", "kind: RegistryProject");
        let error = Selection::parse("test", document.as_bytes()).expect_err("refused");
        assert_eq!(error.code, "init.selection.kind");
        assert!(error.message.contains("ModelSelection"));
    }

    #[test]
    fn an_unknown_key_is_refused_with_the_parser_sentence() {
        let document = format!("{MINIMAL}  - concept: Other\n    colour: blue\n");
        let error = Selection::parse("test", document.as_bytes()).expect_err("refused");
        assert_eq!(error.code, "init.selection.invalid");
        assert!(error.message.contains("colour"), "{}", error.message);
    }

    #[test]
    fn an_empty_document_is_refused() {
        let error = Selection::parse("test", b"").expect_err("refused");
        assert_eq!(error.code, "init.selection.size");
    }
}
