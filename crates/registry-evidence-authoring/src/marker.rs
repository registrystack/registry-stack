//! The marker that anchors a directory as an Evidence authoring project.
//!
//! The marker is deliberately small: its envelope and nothing else. The
//! `apiVersion` names the format version and the `kind` names the one project
//! kind this crate authors today. A directory with no marker is not an error;
//! the marker is how a caller that already found the other authoring parts
//! confirms it read them for the reason it thinks it did, not a gate those
//! parts must pass through.

use registry_platform_yaml::{Decoded, Report};
use serde::Deserialize;

use crate::formats::{decode_authored, AUTHORING_PROJECT};

/// The file name a project root carries when it opts into the marker.
pub const PROJECT_MARKER_FILE: &str = "evidence-project.yaml";

/// The marker document a project root carries: its envelope and no other
/// member. An unknown member is a rejection, the same rule the rest of the
/// authoring form holds to.
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectMarker {}

/// Read a project root's marker document. `file` is the name its diagnostics
/// carry.
///
/// # Errors
///
/// Returns every diagnostic the reader found: a document that is not the
/// marker's envelope, a member the marker no longer takes, or any other
/// member.
pub fn parse_project_marker(file: &str, bytes: &[u8]) -> Result<Decoded<ProjectMarker>, Report> {
    decode_authored(file, bytes, &AUTHORING_PROJECT)
}

/// The exact document `evidencectl new` writes, and the one this crate's own
/// tests and an author's doctor advisory quote rather than restate.
#[must_use]
pub fn default_project_marker_document() -> &'static str {
    "# yaml-language-server: $schema=https://id.registrystack.org/schemas/evidence/authoring-project/authoring-project.v1alpha1.schema.json\n\
     apiVersion: id.registrystack.org/formats/evidence/authoring-project/v1alpha1\n\
     kind: EvidenceAuthoringProject\n"
}

#[cfg(test)]
mod tests {
    use super::{default_project_marker_document, parse_project_marker, PROJECT_MARKER_FILE};
    use crate::formats::{
        envelope_lines, schema_modeline, AUTHORING_PROJECT_API_VERSION, AUTHORING_PROJECT_KIND,
        AUTHORING_PROJECT_SCHEMA_ID,
    };

    fn codes(bytes: &[u8]) -> Vec<String> {
        parse_project_marker(PROJECT_MARKER_FILE, bytes)
            .expect_err("the document is not a valid marker")
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }

    #[test]
    fn the_default_document_parses_to_the_evidence_authoring_marker() {
        let marker = parse_project_marker(
            PROJECT_MARKER_FILE,
            default_project_marker_document().as_bytes(),
        )
        .expect("the default document is a valid marker");
        assert_eq!(marker.document.envelope().kind, AUTHORING_PROJECT_KIND);
    }

    #[test]
    fn the_default_document_is_the_modeline_and_the_envelope() {
        assert_eq!(
            default_project_marker_document(),
            format!(
                "{}{}",
                schema_modeline(AUTHORING_PROJECT_SCHEMA_ID),
                envelope_lines(AUTHORING_PROJECT_API_VERSION, AUTHORING_PROJECT_KIND)
            )
        );
    }

    #[test]
    fn corrupt_yaml_is_rejected() {
        assert_eq!(
            codes(b"apiVersion: [\n"),
            ["yaml.unexpected-end".to_owned()]
        );
    }

    #[test]
    fn an_unknown_member_is_rejected() {
        let document = format!("{}extra: true\n", default_project_marker_document());
        assert_eq!(
            codes(document.as_bytes()),
            ["config.unknown-key".to_owned()]
        );
    }

    #[test]
    fn another_kind_is_rejected() {
        let document = default_project_marker_document()
            .replace("kind: EvidenceAuthoringProject", "kind: EvidenceQuestion");
        assert_eq!(codes(document.as_bytes()), ["config.wrong-kind".to_owned()]);
    }

    #[test]
    fn the_retired_version_and_project_members_name_their_replacement() {
        let document = format!(
            "{}version: 1\nproject: evidence-authoring\n",
            default_project_marker_document()
        );
        assert_eq!(
            codes(document.as_bytes()),
            [
                "config.removed-key".to_owned(),
                "config.removed-key".to_owned()
            ]
        );
        let unmigrated = codes(b"version: 1\nproject: evidence-authoring\n");
        assert!(unmigrated.contains(&"config.missing-envelope".to_owned()));
    }
}
