//! The marker that anchors a directory as an Evidence authoring project.
//!
//! The marker is deliberately small: a format version and the one project
//! kind this crate authors today. A directory with no marker is not an
//! error; the marker is how a caller that already found the other authoring
//! parts confirms it read them for the reason it thinks it did, not a gate
//! those parts must pass through.

use serde::Deserialize;

use crate::finding::{FieldPath, Finding};

/// The file name a project root carries when it opts into the marker.
pub const PROJECT_MARKER_FILE: &str = "evidence-project.yaml";

/// The one marker version this crate parses.
const MARKER_VERSION: u8 = 1;

/// The marker document a project root carries: nothing but its format
/// version and the kind of project it names. An unknown field is a
/// rejection, the same rule the rest of the authoring form holds to.
#[derive(Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ProjectMarker {
    pub version: u8,
    pub project: ProjectKind,
}

/// The one kind of project this crate's marker names today.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ProjectKind {
    EvidenceAuthoring,
}

/// Parse a project root's marker document.
///
/// # Errors
///
/// Returns a [`Finding`] when `bytes` is not the marker's closed shape, or
/// names a version newer or older than the one this crate parses.
pub fn parse_project_marker(bytes: &[u8]) -> Result<ProjectMarker, Finding> {
    let marker: ProjectMarker = serde_norway::from_slice(bytes).map_err(|error| {
        Finding::new(
            FieldPath::root(),
            "project-marker-parse",
            format!("{PROJECT_MARKER_FILE} does not parse: {error}"),
        )
    })?;
    if marker.version != MARKER_VERSION {
        return Err(Finding::new(
            FieldPath::root().key("version"),
            "project-marker-version",
            format!("{PROJECT_MARKER_FILE} version must be {MARKER_VERSION}"),
        ));
    }
    Ok(marker)
}

/// The exact document `evidencectl new` writes, and the one this crate's own
/// tests and an author's doctor advisory quote rather than restate.
#[must_use]
pub fn default_project_marker_document() -> &'static str {
    "version: 1\nproject: evidence-authoring\n"
}

#[cfg(test)]
mod tests {
    use super::{default_project_marker_document, parse_project_marker, ProjectKind};

    #[test]
    fn the_default_document_parses_to_the_evidence_authoring_marker() {
        let marker = parse_project_marker(default_project_marker_document().as_bytes())
            .expect("the default document is a valid marker");
        assert_eq!(marker.version, 1);
        assert_eq!(marker.project, ProjectKind::EvidenceAuthoring);
    }

    #[test]
    fn the_default_document_is_exactly_two_lines() {
        assert_eq!(
            default_project_marker_document(),
            "version: 1\nproject: evidence-authoring\n"
        );
    }

    #[test]
    fn corrupt_yaml_is_rejected() {
        let error = parse_project_marker(b"version: 1\nproject: [\n")
            .expect_err("truncated YAML does not parse");
        assert_eq!(error.code, "project-marker-parse");
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        let error = parse_project_marker(b"version: 1\nproject: evidence-authoring\nextra: true\n")
            .expect_err("an unknown field is not the closed marker shape");
        assert_eq!(error.code, "project-marker-parse");
    }

    #[test]
    fn an_unknown_project_kind_is_rejected() {
        let error = parse_project_marker(b"version: 1\nproject: something-else\n")
            .expect_err("the project kind is a closed enum");
        assert_eq!(error.code, "project-marker-parse");
    }

    #[test]
    fn a_wrong_version_is_rejected() {
        let error = parse_project_marker(b"version: 2\nproject: evidence-authoring\n")
            .expect_err("this crate parses only version 1");
        assert_eq!(error.code, "project-marker-version");
    }
}
