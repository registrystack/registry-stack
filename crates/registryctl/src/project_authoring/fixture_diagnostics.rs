// SPDX-License-Identifier: Apache-2.0
//! Registryctl-owned metadata for the closed offline-fixture error catalog.

use super::FixtureSafeCode;

/// Static reference metadata for one offline fixture failure code.
///
/// The immutable fixture-coverage set owns the closed code type. This module
/// owns the operator-safe prose used by generated references, so the
/// aggregation layer does not copy product metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FixtureDiagnosticDefinition {
    pub code: FixtureSafeCode,
    pub safe_meaning: &'static str,
    pub rule: &'static str,
    pub safe_remediation: &'static str,
}

macro_rules! fixture_diagnostic {
    ($code:ident, $meaning:literal, $rule:literal, $remediation:literal) => {
        FixtureDiagnosticDefinition {
            code: FixtureSafeCode::$code,
            safe_meaning: $meaning,
            rule: $rule,
            safe_remediation: $remediation,
        }
    };
}

/// Complete Registryctl offline-fixture diagnostic catalog in lexical code
/// order.
pub(crate) const FIXTURE_DIAGNOSTIC_DEFINITIONS: &[FixtureDiagnosticDefinition] = &[
    fixture_diagnostic!(
        FailureSubjectMismatch,
        "The source observation did not preserve the requested subject binding.",
        "subject_binding",
        "Correct the synthetic subject evidence or the reviewed subject comparison."
    ),
    fixture_diagnostic!(
        FixtureExecutionContractInvalid,
        "Fixture execution violated the compiled offline plan contract.",
        "compiled_execution_contract",
        "Align the fixture with the exact compiled integration plan."
    ),
    fixture_diagnostic!(
        FixtureProfileNotFound,
        "The fixture profile pin did not select one exact compiled plan.",
        "profile_pin",
        "Select one compiled integration profile."
    ),
    fixture_diagnostic!(
        FixtureRequestMismatch,
        "The rendered request or call order did not match the fixture expectation.",
        "request_authority_and_order",
        "Align the fixture request expectation with the compiled plan."
    ),
    fixture_diagnostic!(
        FixtureSourceOperationUnknown,
        "The fixture named a source operation outside the compiled plan.",
        "source_operation_closure",
        "Use only source operations declared by the compiled plan."
    ),
    fixture_diagnostic!(
        InputPatternMismatch,
        "A synthetic fixture input did not satisfy its compiled contract.",
        "compiled_input_contract",
        "Correct the synthetic input shape."
    ),
    fixture_diagnostic!(
        RedactedUnclassifiedError,
        "An error outside the reviewed safe allow-list was redacted.",
        "safe_error_allow_list",
        "Use classified fixture evidence or inspect private local logs without publishing values."
    ),
    fixture_diagnostic!(
        SourceCallBudgetExceeded,
        "Fixture execution exceeded the compiled source-call budget.",
        "source_call_budget",
        "Reduce source calls or revise the reviewed bounded plan."
    ),
    fixture_diagnostic!(
        SourceCardinalityViolation,
        "The synthetic source response violated the compiled cardinality contract.",
        "source_cardinality",
        "Correct the synthetic response cardinality."
    ),
    fixture_diagnostic!(
        SourceDeadlineExceeded,
        "The synthetic source interaction exceeded its deadline.",
        "source_deadline",
        "Align the timeout fixture with the compiled deadline behavior."
    ),
    fixture_diagnostic!(
        SourceResponseMalformed,
        "The synthetic source response violated its closed response contract.",
        "source_response_contract",
        "Correct the synthetic response shape."
    ),
    fixture_diagnostic!(
        SourceResponseTooLarge,
        "The synthetic source response exceeded its compiled byte bound.",
        "source_response_byte_bound",
        "Reduce the synthetic response below the compiled bound."
    ),
    fixture_diagnostic!(
        SourceStatusRejected,
        "The synthetic source returned a status outside the accepted mapping.",
        "source_status_mapping",
        "Use a reviewed status mapping or correct the fixture status."
    ),
    fixture_diagnostic!(
        SourceUnavailable,
        "The synthetic source was unavailable.",
        "source_availability",
        "Correct the offline source observation for the intended availability case."
    ),
    fixture_diagnostic!(
        SourceUnavailableLegacy,
        "The synthetic source was unavailable under the retained legacy code.",
        "legacy_source_availability",
        "Prefer source.unavailable for new fixtures while retaining compatible evidence."
    ),
];

/// Return the single catalog definition for a closed fixture code.
///
/// The exhaustive match makes a newly added fixture code a compile failure
/// until the product-owned reference catalog is updated.
pub(crate) const fn fixture_diagnostic_definition(
    code: FixtureSafeCode,
) -> &'static FixtureDiagnosticDefinition {
    match code {
        FixtureSafeCode::FailureSubjectMismatch => &FIXTURE_DIAGNOSTIC_DEFINITIONS[0],
        FixtureSafeCode::FixtureExecutionContractInvalid => &FIXTURE_DIAGNOSTIC_DEFINITIONS[1],
        FixtureSafeCode::FixtureProfileNotFound => &FIXTURE_DIAGNOSTIC_DEFINITIONS[2],
        FixtureSafeCode::FixtureRequestMismatch => &FIXTURE_DIAGNOSTIC_DEFINITIONS[3],
        FixtureSafeCode::FixtureSourceOperationUnknown => &FIXTURE_DIAGNOSTIC_DEFINITIONS[4],
        FixtureSafeCode::InputPatternMismatch => &FIXTURE_DIAGNOSTIC_DEFINITIONS[5],
        FixtureSafeCode::RedactedUnclassifiedError => &FIXTURE_DIAGNOSTIC_DEFINITIONS[6],
        FixtureSafeCode::SourceCallBudgetExceeded => &FIXTURE_DIAGNOSTIC_DEFINITIONS[7],
        FixtureSafeCode::SourceCardinalityViolation => &FIXTURE_DIAGNOSTIC_DEFINITIONS[8],
        FixtureSafeCode::SourceDeadlineExceeded => &FIXTURE_DIAGNOSTIC_DEFINITIONS[9],
        FixtureSafeCode::SourceResponseMalformed => &FIXTURE_DIAGNOSTIC_DEFINITIONS[10],
        FixtureSafeCode::SourceResponseTooLarge => &FIXTURE_DIAGNOSTIC_DEFINITIONS[11],
        FixtureSafeCode::SourceStatusRejected => &FIXTURE_DIAGNOSTIC_DEFINITIONS[12],
        FixtureSafeCode::SourceUnavailable => &FIXTURE_DIAGNOSTIC_DEFINITIONS[13],
        FixtureSafeCode::SourceUnavailableLegacy => &FIXTURE_DIAGNOSTIC_DEFINITIONS[14],
    }
}
