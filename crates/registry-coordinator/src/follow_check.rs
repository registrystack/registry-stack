// SPDX-License-Identifier: Apache-2.0
//! `check` warnings for a wait that follows a BReg Proposal: a wait longer
//! than 90 days holds a run across drain-based upgrades, and a wait with no
//! `onTimeout` fails the run with `wait-timed-out` when no decision comes.

use registry_platform_yaml::{escape_pointer_segment, Diagnostic, Document, Severity};

use crate::definition::{CompletionKind, Step, Workflow};

/// Ninety days: the longest Proposal follow `check` accepts without a warning.
const LONG_FOLLOW_SECONDS: u32 = 90 * 86_400;

/// The follow warnings for every wait-for step on a Proposal completion,
/// placed at the authored step in `document`.
pub(crate) fn warnings(workflow: &Workflow, document: &Document) -> Vec<Diagnostic> {
    let mut found = Vec::new();
    for (name, step) in &workflow.steps {
        let Step::WaitFor {
            wait_for,
            timeout_seconds,
            on_timeout,
            ..
        } = step
        else {
            continue;
        };
        if !workflow
            .completion(wait_for)
            .is_some_and(|completion| matches!(completion.kind, CompletionKind::BregProposal {}))
        {
            continue;
        }
        let pointer = format!("/workflow/steps/{}", escape_pointer_segment(name));
        if *timeout_seconds > LONG_FOLLOW_SECONDS {
            found.push(document.diagnostic_at_value(
                Severity::Warning,
                "coordinator.follow.long",
                &format!("{pointer}/timeoutSeconds"),
                "This wait follows a request for more than 90 days. Long waits delay drain-based upgrades; shorten the time limit or route the timeout.",
                "Set timeoutSeconds to 7776000 or less, or route the timeout to a step that handles the request.",
            ));
        }
        if on_timeout.is_none() {
            found.push(document.diagnostic_at_value(
                Severity::Warning,
                "coordinator.follow.timeout-unrouted",
                &pointer,
                "This wait has no route for a request that gets no decision in time, so the run fails with wait-timed-out. Add onTimeout.",
                "Add onTimeout naming the step that handles a request with no decision.",
            ));
        }
    }
    found
}
