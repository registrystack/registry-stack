//! The authored Evidence formats, and the one way each is read.
//!
//! Every document an adopter writes under an authoring project is read here,
//! through the shared Registry Stack reader: one YAML subset, one envelope
//! check, typed decoding, and diagnostics that carry a code, a JSON pointer,
//! a line and column, a message, and the action that fixes the problem. The
//! command line and the language server both call these functions, so they
//! report the same sentences at the same places.
//!
//! An authored file is never expanded: a `${...}` expression in one is
//! refused where it is written (CFG-SEC-2). Substitution belongs to the
//! runtime's operator file alone.
//!
//! Like the rest of this crate, nothing here reads a file. The caller hands
//! over the bytes and the name the diagnostics should carry.

use registry_platform_yaml::{
    ApiVersion, Decoded, Diagnostic, Document, EnvelopeRule, Expect, FormatSpec, Node, Reader,
    Refusal, RemovedKey, Report, ScalarHook, ScalarSite, Severity,
};
use serde::de::DeserializeOwned;

use crate::{
    finding::Finding,
    model::{AccessPolicy, Question},
    validate::{validate_access_policy, validate_question},
};

/// The `apiVersion` of the project marker, `evidence-project.yaml`.
pub const AUTHORING_PROJECT_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/authoring-project/v1alpha1";
/// The `kind` of the project marker.
pub const AUTHORING_PROJECT_KIND: &str = "EvidenceAuthoringProject";
/// The `apiVersion` of a question under `questions/`.
pub const QUESTION_API_VERSION: &str = "id.registrystack.org/formats/evidence/question/v1alpha1";
/// The `kind` of a question.
pub const QUESTION_KIND: &str = "EvidenceQuestion";
/// The published `$id` of the project marker's JSON Schema.
pub const AUTHORING_PROJECT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/authoring-project/authoring-project.v1alpha1.schema.json";
/// The published `$id` of a question's JSON Schema.
pub const QUESTION_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/question/question.v1alpha1.schema.json";
/// The published `$id` of a local access policy's JSON Schema.
pub const ACCESS_POLICY_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/access-policy/access-policy.v1alpha1.schema.json";
/// The `apiVersion` of a local access policy under `access/policies/`.
pub const ACCESS_POLICY_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/access-policy/v1alpha1";
/// The `kind` of a local access policy.
pub const ACCESS_POLICY_KIND: &str = "EvidenceAccessPolicy";
/// The `apiVersion` of a local access client under `access/clients/`.
pub const ACCESS_CLIENT_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/access-client/v1alpha1";
/// The `kind` of a local access client.
pub const ACCESS_CLIENT_KIND: &str = "EvidenceAccessClient";
/// The `apiVersion` of a deployment target's `governance.yaml`.
pub const TARGET_GOVERNANCE_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/target-governance/v1alpha1";
/// The `kind` of a deployment target's governance.
pub const TARGET_GOVERNANCE_KIND: &str = "EvidenceTargetGovernance";
/// The `apiVersion` of a target's `settings.yaml`.
pub const TARGET_SETTINGS_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/target-settings/v1alpha1";
/// The `kind` of a target's settings.
pub const TARGET_SETTINGS_KIND: &str = "EvidenceTargetSettings";
/// The `apiVersion` of a materialized source mock plan.
pub const MOCK_PLAN_API_VERSION: &str = "id.registrystack.org/formats/evidence/mock-plan/v1alpha1";
/// The `kind` of a materialized source mock plan.
pub const MOCK_PLAN_KIND: &str = "EvidenceMockPlan";

const NO_FORMAT_VERSION: &str = "Remove `version`; `apiVersion` names the format version.";

/// The marker that anchors a directory as an Evidence authoring project.
pub const AUTHORING_PROJECT: FormatSpec<'static> = FormatSpec {
    kind: AUTHORING_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(AUTHORING_PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/version",
            replacement: NO_FORMAT_VERSION,
        },
        RemovedKey {
            pointer: "/project",
            replacement: "Remove `project`; `kind: EvidenceAuthoringProject` names the project.",
        },
    ],
};

/// One authored question.
pub const QUESTION: FormatSpec<'static> = FormatSpec {
    kind: QUESTION_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(QUESTION_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// One local access policy.
pub const ACCESS_POLICY: FormatSpec<'static> = FormatSpec {
    kind: ACCESS_POLICY_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ACCESS_POLICY_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[RemovedKey {
        pointer: "/version",
        replacement: NO_FORMAT_VERSION,
    }],
};

/// One local access client.
pub const ACCESS_CLIENT: FormatSpec<'static> = FormatSpec {
    kind: ACCESS_CLIENT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ACCESS_CLIENT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[RemovedKey {
        pointer: "/version",
        replacement: NO_FORMAT_VERSION,
    }],
};

/// A deployment target's governance, compiled into the signed bundle.
pub const TARGET_GOVERNANCE: FormatSpec<'static> = FormatSpec {
    kind: TARGET_GOVERNANCE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(TARGET_GOVERNANCE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[RemovedKey {
        pointer: "/version",
        replacement: NO_FORMAT_VERSION,
    }],
};

/// A target's settings, from which `evidencectl target` writes the target.
pub const TARGET_SETTINGS: FormatSpec<'static> = FormatSpec {
    kind: TARGET_SETTINGS_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(TARGET_SETTINGS_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/formatVersion",
            replacement: "Remove `formatVersion`; `apiVersion` names the format version.",
        },
        RemovedKey {
            pointer: "/governance/version",
            replacement: NO_FORMAT_VERSION,
        },
    ],
};

/// A materialized source mock plan.
pub const MOCK_PLAN: FormatSpec<'static> = FormatSpec {
    kind: MOCK_PLAN_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(MOCK_PLAN_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[RemovedKey {
        pointer: "/version",
        replacement: NO_FORMAT_VERSION,
    }],
};

/// One authored source under `sources/`. Sources carry no envelope yet: they
/// are also written by `evidencectl source add` and the source import, which
/// write the same shape.
pub const SOURCE: FormatSpec<'static> = FormatSpec {
    kind: "EvidenceSource",
    envelope: EnvelopeRule::Exempt {
        reason: "sources written by the source import carry no envelope yet",
    },
    removed_keys: &[],
};

/// One authored selector under `selectors/`, exempt for the same reason as a
/// source.
pub const SELECTOR: FormatSpec<'static> = FormatSpec {
    kind: "EvidenceSelector",
    envelope: EnvelopeRule::Exempt {
        reason: "selectors written by the source import carry no envelope yet",
    },
    removed_keys: &[],
};

/// The formats an authoring project's files may declare by envelope, for a
/// read that identifies a file by its `kind`.
pub const ENVELOPED_FORMATS: &[FormatSpec<'static>] = &[
    AUTHORING_PROJECT,
    QUESTION,
    ACCESS_POLICY,
    ACCESS_CLIENT,
    TARGET_GOVERNANCE,
    TARGET_SETTINGS,
    MOCK_PLAN,
];

/// The code a `${...}` expression in an authored file is refused with.
pub const SUBSTITUTION_NOT_ALLOWED: &str = "config.substitution-not-allowed";

/// Refuses every environment expression in an authored file, at the key or
/// value it is written in.
struct AuthoredExpressions;

impl AuthoredExpressions {
    fn check(text: &str) -> Result<(), Refusal> {
        if contains_environment_expression(text) {
            return Err(Refusal {
                code: SUBSTITUTION_NOT_ALLOWED.to_owned(),
                message: "a `${...}` expression is written in an authored file; substitution \
                          applies to runtime.yaml only"
                    .to_owned(),
                suggested_action: "Write the value in the authored file directly; authored \
                                   files are not expanded."
                    .to_owned(),
            });
        }
        Ok(())
    }
}

impl ScalarHook for AuthoredExpressions {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        Self::check(site.text)
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Self::check(site.text).map(|()| None)
    }
}

/// Whether `text` holds a `${NAME}`, `${NAME:-...}`, or `${NAME:?...}`
/// expression, the forms the runtime's operator file expands.
#[must_use]
pub fn contains_environment_expression(text: &str) -> bool {
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let name_end = after
            .find(|character: char| character != '_' && !character.is_ascii_alphanumeric())
            .unwrap_or(after.len());
        let name = &after[..name_end];
        let tail = &after[name_end..];
        if valid_environment_name(name)
            && (tail.starts_with('}') || tail.starts_with(":-") || tail.starts_with(":?"))
        {
            return true;
        }
        rest = after;
    }
    false
}

fn valid_environment_name(name: &str) -> bool {
    let mut characters = name.chars();
    matches!(characters.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

/// Read one authored document of `format`: its YAML, its envelope, and its
/// removed keys, refusing every `${...}` expression.
///
/// # Errors
///
/// Returns every diagnostic the reader found.
pub fn read_authored(
    file: &str,
    bytes: &[u8],
    format: &FormatSpec<'_>,
) -> Result<Document, Report> {
    let mut hook = AuthoredExpressions;
    Reader::new(file)
        .with_hook(&mut hook)
        .read(bytes, &Expect::one(format))
}

/// Read one authored document that may be any of `formats`, identified by its
/// envelope.
///
/// # Errors
///
/// Returns every diagnostic the reader found, including a foreign `kind`.
pub fn read_authored_any(
    file: &str,
    bytes: &[u8],
    formats: &[FormatSpec<'_>],
) -> Result<Document, Report> {
    let mut hook = AuthoredExpressions;
    Reader::new(file)
        .with_hook(&mut hook)
        .read(bytes, &Expect::new(formats))
}

/// Read one authored document of `format` and decode it into `T`.
///
/// # Errors
///
/// Returns every diagnostic the reader found.
pub fn decode_authored<T: DeserializeOwned>(
    file: &str,
    bytes: &[u8],
    format: &FormatSpec<'_>,
) -> Result<Decoded<T>, Report> {
    let mut hook = AuthoredExpressions;
    Reader::new(file)
        .with_hook(&mut hook)
        .decode(bytes, &Expect::one(format))
}

/// Read an authored file whose grammar Registry Stack does not own, such as
/// a reviewed JSON Schema, through the shared YAML subset alone: no envelope
/// and no typed decoding, but the same size bound, the same refusals, and no
/// `${...}` expression.
///
/// # Errors
///
/// Returns every diagnostic the reader found.
pub fn scan_authored(file: &str, bytes: &[u8]) -> Result<Option<Node>, Report> {
    let mut hook = AuthoredExpressions;
    Reader::new(file).with_hook(&mut hook).scan(bytes)
}

/// Read and check one authored question: the reader's diagnostics first, then
/// every finding of the authoring checks, placed where each is written.
///
/// # Errors
///
/// Returns the report when the question has any error.
pub fn check_question(file: &str, bytes: &[u8]) -> Result<Decoded<Question>, Report> {
    let decoded = decode_authored::<Question>(file, bytes, &QUESTION)?;
    let report = findings_report(
        &decoded.document,
        "question",
        validate_question(&decoded.value),
    );
    if report.has_errors() {
        return Err(report);
    }
    Ok(decoded)
}

/// Read and check one local access policy.
///
/// # Errors
///
/// Returns the report when the policy has any error.
pub fn check_access_policy(file: &str, bytes: &[u8]) -> Result<Decoded<AccessPolicy>, Report> {
    let decoded = decode_authored::<AccessPolicy>(file, bytes, &ACCESS_POLICY)?;
    let report = findings_report(
        &decoded.document,
        "access-policy",
        validate_access_policy(&decoded.value),
    );
    if report.has_errors() {
        return Err(report);
    }
    Ok(decoded)
}

/// Every finding of an authoring check as an error diagnostic, placed at the
/// value it concerns or, when that value is absent, at the nearest member
/// that is written.
#[must_use]
pub fn findings_report(document: &Document, area: &str, findings: Vec<Finding>) -> Report {
    let mut report = Report::new(
        findings
            .iter()
            .map(|finding| finding_diagnostic(document, area, finding))
            .collect(),
    );
    report.set_files_checked(1);
    report
}

/// One finding as a diagnostic: the code under `evidence.<area>.`, the
/// finding's sentence, and the action that answers it.
#[must_use]
pub fn finding_diagnostic(document: &Document, area: &str, finding: &Finding) -> Diagnostic {
    let pointer = finding.field.to_json_pointer();
    diagnostic_near(
        document,
        &finding_code(area, finding.code),
        &pointer,
        &finding.message,
        finding_action(finding.code),
    )
}

/// An error about `pointer`, placed at its value or at the nearest written
/// ancestor when the member is absent. The path stays the one the problem
/// concerns.
#[must_use]
pub fn diagnostic_near(
    document: &Document,
    code: &str,
    pointer: &str,
    message: &str,
    suggested_action: &str,
) -> Diagnostic {
    let mut placed = pointer;
    while document.span_of(placed).is_none() && !placed.is_empty() {
        placed = placed.rfind('/').map_or("", |slash| &placed[..slash]);
    }
    let mut diagnostic = if placed == pointer {
        document.diagnostic_at_value(Severity::Error, code, placed, message, suggested_action)
    } else {
        document.diagnostic_at_key(Severity::Error, code, placed, message, suggested_action)
    };
    diagnostic.path = pointer.to_owned();
    diagnostic
}

/// The diagnostic code of one finding: `evidence.<area>.<condition>`, with the
/// area dropped from the front of the finding's own code when it repeats it.
/// A finding that already carries a full dotted code keeps it.
#[must_use]
pub fn finding_code(area: &str, code: &str) -> String {
    if code.contains('.') {
        return code.to_owned();
    }
    let condition = code
        .strip_prefix(area)
        .and_then(|rest| rest.strip_prefix('-'))
        .unwrap_or(code);
    format!("evidence.{area}.{condition}")
}

/// The action that answers one finding, by its code.
#[must_use]
pub fn finding_action(code: &str) -> &'static str {
    match code {
        "question-identifier" => {
            "Name the question with a lowercase local identifier that matches its file name."
        }
        "question-text" => "Write the question as one bounded sentence.",
        "operation-identifier" => {
            "Name an operationId the project's OpenAPI description declares."
        }
        "subject-count" | "subject-declaration" | "subject-identifier" | "subject-role-unique"
        | "subject-selector-shape" | "subject-profile-alternatives" | "subject-source-context" => {
            "Declare each subject once, with a unique role and either a selector or profiles, as the message describes."
        }
        "source-declaration" | "source-reference" => {
            "Name a source under sources/, or an operation of the project's OpenAPI description."
        }
        "fact-count" | "fact-name" | "fact-path" | "fact-combination" => {
            "Give each fact a unique name, a JSON Pointer path, and `combine: collect` exactly when the path visits a collection."
        }
        "collection-bounds" => {
            "Bound each collection the facts visit, by its JSON Pointer, with at most 16 entries."
        }
        "answer-count" | "answer-concept-identifier" | "answer-concept-unique" => {
            "Give each answer a unique concept named by a lowercase local identifier."
        }
        "boolean-answer" | "controlled-category-values" | "controlled-category-bounds"
        | "bounded-integer-values" | "bounded-integer-bounds" | "bounded-integer-bounds-missing"
        | "bounded-identifier-bounds" | "bounded-identifier-prefix" | "bounded-identifier-shape"
        | "identifier-constraints-form" => {
            "Declare exactly the constraints the answer's type takes, as the message describes."
        }
        "structured-answer-schema" | "structured-answer-size" | "structured-answer-constraints"
        | "answer-schema-path" => {
            "Name a reviewed schema under schemas/ and bound the structured value's serialized size."
        }
        "disclosure-allow" => "Allow only concepts the question's answers declare, each once.",
        "response-formats" | "sd-jwt-vc-format" | "sd-jwt-vc-claim-name" | "sd-jwt-vc-claim-unique" => {
            "Offer sd-jwt-vc only with a unique SD-JWT VC claim name for each answer that sets one."
        }
        "derivation-compile" | "derivation-answer-count" | "derivation-answer-signature"
        | "derivation-function-unique" | "derivation-reserved-entry-point" => {
            "Correct the derivation script so it compiles and defines `answer` once with the documented signature."
        }
        "derivation-fact-undeclared" => {
            "Declare every fact the derivation reads under the question's source facts, or stop reading it."
        }
        "access-policy-identifier" => {
            "Name the policy with a lowercase local identifier that matches its file name."
        }
        "access-policy-question-count" | "access-policy-question-order" => {
            "List each question the policy admits once, in sorted order."
        }
        "access-policy-grant-kind" | "access-policy-grant-source" | "access-policy-grant-clients"
        | "access-policy-grant-bindings" | "access-policy-grant-binding-shape" => {
            "Declare the task grant's kind, an https source issuer, its requester clients, and one binding per bound question role."
        }
        "kebab-case" | "date-time" | "x-evidencectl-mock" | "x-evidencectl-recursive-ref" => {
            "Correct the OpenAPI description as the message describes."
        }
        _ => "Correct the named member as the message describes, then check the project again.",
    }
}

/// The first line an authored file carries, naming the published `$id` of
/// its format's JSON Schema, so a YAML editor finds the schema without
/// configuration.
#[must_use]
pub fn schema_modeline(schema_id: &str) -> String {
    format!("# yaml-language-server: $schema={schema_id}\n")
}

/// The envelope lines an authored file of `format` opens with, after its
/// modeline.
#[must_use]
pub fn envelope_lines(api_version: &str, kind: &str) -> String {
    format!("apiVersion: {api_version}\nkind: {kind}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marker::default_project_marker_document;

    const MARKER: &str = "apiVersion: id.registrystack.org/formats/evidence/authoring-project/v1alpha1\nkind: EvidenceAuthoringProject\n";

    fn codes(report: &Report) -> Vec<&str> {
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect()
    }

    #[test]
    fn the_default_marker_reads_as_the_project_marker() {
        let document = read_authored(
            "evidence-project.yaml",
            default_project_marker_document().as_bytes(),
            &AUTHORING_PROJECT,
        )
        .expect("the default marker is valid");
        assert_eq!(document.envelope().kind, AUTHORING_PROJECT_KIND);
        assert!(default_project_marker_document().starts_with("# yaml-language-server: $schema="));
    }

    #[test]
    fn the_retired_marker_members_are_refused_with_their_replacement() {
        let report = read_authored(
            "evidence-project.yaml",
            format!("{MARKER}version: 1\nproject: evidence-authoring\n").as_bytes(),
            &AUTHORING_PROJECT,
        )
        .expect_err("removed keys are refused");
        assert_eq!(codes(&report), ["config.removed-key", "config.removed-key"]);
    }

    #[test]
    fn a_marker_without_an_envelope_is_refused() {
        let report = read_authored(
            "evidence-project.yaml",
            b"version: 1\nproject: evidence-authoring\n",
            &AUTHORING_PROJECT,
        )
        .expect_err("the envelope is required");
        assert!(codes(&report).contains(&"config.missing-envelope"));
    }

    #[test]
    fn an_environment_expression_is_refused_in_an_authored_value_and_key() {
        let text = format!("{MARKER}note: ${{HOME}}\n");
        let report = read_authored("evidence-project.yaml", text.as_bytes(), &AUTHORING_PROJECT)
            .expect_err("authored files are not expanded");
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.code, SUBSTITUTION_NOT_ALLOWED);
        assert_eq!(diagnostic.path, "/note");
        assert!(!diagnostic.message.contains("HOME"));
        assert!(diagnostic.suggested_action.contains("not expanded"));
        let source = diagnostic.source.as_ref().expect("placed");
        assert_eq!((source.line, source.column), (Some(3), Some(7)));
    }

    #[test]
    fn text_that_only_resembles_an_expression_is_left_alone() {
        assert!(!contains_environment_expression("costs ${ and more"));
        assert!(!contains_environment_expression("${1ABC}"));
        assert!(contains_environment_expression("prefix-${NAME:-fallback}"));
        assert!(contains_environment_expression("${_X}"));
    }

    #[test]
    fn a_document_of_exactly_the_size_cap_is_read_and_one_byte_more_is_refused() {
        let cap = registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES;
        let mut text = default_project_marker_document().to_owned();
        while text.len() < cap {
            let room = cap - text.len();
            let line = if room > 81 { 80 } else { room - 1 };
            text.push('#');
            text.push_str(&" ".repeat(line.saturating_sub(1)));
            text.push('\n');
        }
        assert_eq!(text.len(), cap);
        read_authored("evidence-project.yaml", text.as_bytes(), &AUTHORING_PROJECT)
            .expect("a file of exactly the cap is accepted");
        text.push('\n');
        let report = read_authored("evidence-project.yaml", text.as_bytes(), &AUTHORING_PROJECT)
            .expect_err("one byte over the cap is refused");
        assert_eq!(codes(&report), ["yaml.too-large"]);
    }

    #[test]
    fn finding_codes_name_their_area_once() {
        assert_eq!(
            finding_code("question", "question-text"),
            "evidence.question.text"
        );
        assert_eq!(
            finding_code("question", "answer-concept-unique"),
            "evidence.question.answer-concept-unique"
        );
        assert_eq!(
            finding_code("access-policy", "access-policy-grant-kind"),
            "evidence.access-policy.grant-kind"
        );
        assert_eq!(
            finding_code("derivation", "derivation-compile"),
            "evidence.derivation.compile"
        );
        assert_eq!(
            finding_code("schema", "evidence.answer-schema.open-object"),
            "evidence.answer-schema.open-object"
        );
    }
}
