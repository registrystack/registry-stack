//! Pure structural checks for normalized Evidence acquisition plans.
//!
//! The compiler projects these authored values into the retained runtime
//! configuration. Checking the plan here gives an author field-level findings
//! before that projection, without introducing another lowering path.

use crate::{project::EvidenceProject, Finding};

/// Route control flow and final-fact closure now belong to the checked pack.
/// Project validation owns the remaining authoring checks, so this retained
/// entry point stays pure while downstream callers migrate off the old module.
#[must_use]
pub fn validate(project: &EvidenceProject) -> Vec<Finding> {
    crate::project::validate_project(project)
        .into_iter()
        .filter(|finding| {
            finding.code.starts_with("source-") || finding.code == "acquisition-source"
        })
        .collect()
}
