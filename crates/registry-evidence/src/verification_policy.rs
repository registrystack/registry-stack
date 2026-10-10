// SPDX-License-Identifier: Apache-2.0
//! The two relying-procedure verification policy documents: the Version 1
//! document `evidence verify` reads and the holder-bound document
//! `evidence verify-presentation` reads.
//!
//! Both are read through the shared configuration reader into closed reader
//! types, checked, and only then handed to the portable verifier's document
//! types, which stay the serde wire types the client bindings share. A
//! refusal names the file, the member, its line and column, and the fix, and
//! never repeats a value: a policy pins nonces and subject bindings
//! (CFG-SEC-3). `evidence check-policy` reports those diagnostics; the two
//! verify commands report only their closed `malformed` class, as their
//! frozen contracts state.

use std::path::Path;

use registry_evidence_verifier::verifier::{
    EvidenceVerificationPolicyDocument, HolderBoundDeclaration,
    HolderBoundPresentationPolicyDocument, MAXIMUM_ASSERTION_LIFETIME_SECONDS,
    MAXIMUM_CLOCK_SKEW_SECONDS, MAXIMUM_EXPECTED_LIST_ITEMS, MAXIMUM_KEY_BINDING_AGE_SECONDS,
    MINIMUM_ASSERTION_LIFETIME_SECONDS, MINIMUM_EXPECTED_LIST_ITEMS,
    MINIMUM_KEY_BINDING_AGE_SECONDS,
};
use registry_evidence_verifier::AssuranceProfile;
use registry_platform_yaml::{
    shape_union, BoundedU32, BoundedU64, Diagnostic, Document, EnvelopeRule, Expect, FormatSpec,
    Reader, Refusal, Report, ScalarHook, ScalarSite, Severity, UniqueList, MAXIMUM_DOCUMENT_BYTES,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};

use registry_platform_config::contains_environment_expression;

/// The kind the reader names a Version 1 verification policy by.
pub const VERIFICATION_POLICY_KIND: &str = "EvidenceVerificationPolicy";

/// The kind the reader names a holder-bound verification policy by.
pub const HOLDER_BOUND_POLICY_KIND: &str = "EvidenceHolderBoundVerificationPolicy";

/// The Version 1 verification policy format. Its frozen contract declares
/// neither `apiVersion` nor `kind`; the envelope arrives with the move to
/// the stable format line.
pub const VERIFICATION_POLICY_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: VERIFICATION_POLICY_KIND,
    envelope: EnvelopeRule::Exempt {
        reason: "the frozen Version 1 verification policy contract declares no apiVersion or kind",
    },
    removed_keys: &[],
};

/// The holder-bound verification policy format, exempt from the envelope for
/// the same reason. It is told apart by its required `subjectBinding`.
pub const HOLDER_BOUND_POLICY_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: HOLDER_BOUND_POLICY_KIND,
    envelope: EnvelopeRule::Exempt {
        reason:
            "the frozen holder-bound verification policy contract declares no apiVersion or kind",
    },
    removed_keys: &[],
};

/// Most expected subjects one policy pins, as both contracts state.
const MAXIMUM_EXPECTED_SUBJECTS: usize = 8;
/// Most expected outputs one policy pins, as both contracts state.
const MAXIMUM_EXPECTED_OUTPUTS: usize = 16;
/// Most revoked service-key thumbprints one policy lists, as both contracts
/// state.
const MAXIMUM_REVOKED_KEY_IDS: usize = 33;

// The list bounds below are written as literals because a const generic
// cannot convert the verifier's `usize` constants; these hold them equal.
const _: () = assert!(MINIMUM_EXPECTED_LIST_ITEMS == 1 && MAXIMUM_EXPECTED_LIST_ITEMS == 64);

type AssertionLifetime =
    BoundedU64<MINIMUM_ASSERTION_LIFETIME_SECONDS, MAXIMUM_ASSERTION_LIFETIME_SECONDS>;
type ClockSkew = BoundedU64<0, MAXIMUM_CLOCK_SKEW_SECONDS>;
type KeyBindingAge = BoundedU64<MINIMUM_KEY_BINDING_AGE_SECONDS, MAXIMUM_KEY_BINDING_AGE_SECONDS>;
type ListItems = BoundedU32<1, 64>;

/// Read a Version 1 verification policy. `file` is the name the diagnostics
/// carry.
pub fn read_verification_policy(
    file: &str,
    bytes: &[u8],
) -> Result<EvidenceVerificationPolicyDocument, Report> {
    read::<VerificationPolicyFile, _>(file, bytes, &VERIFICATION_POLICY_FORMAT)
}

/// Read a holder-bound verification policy. `file` is the name the
/// diagnostics carry.
pub fn read_holder_bound_policy(
    file: &str,
    bytes: &[u8],
) -> Result<HolderBoundPresentationPolicyDocument, Report> {
    read::<HolderBoundPolicyFile, _>(file, bytes, &HOLDER_BOUND_POLICY_FORMAT)
}

/// Which policy document a check reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyKind {
    /// The Version 1 document `evidence verify` reads.
    Verification,
    /// The holder-bound document `evidence verify-presentation` reads.
    HolderBound,
}

/// The outcome of checking one policy file offline.
pub struct PolicyCheck {
    /// Every diagnostic found, with the number of files read.
    pub report: Report,
    /// The file could not be read, so the check could not finish (exit 3).
    pub unavailable: bool,
}

/// Check one policy file offline, exactly as the verify command that reads
/// it would read it.
///
/// At most one byte more than the reader's size cap is read, so an oversized
/// file reaches the reader as oversized and is refused there with the
/// diagnostic every format shares.
pub fn check_policy(path: &Path, kind: PolicyKind) -> PolicyCheck {
    let file = path.display().to_string();
    let readable = std::fs::metadata(path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .and_then(|_| read_capped(path).ok());
    let Some(bytes) = readable else {
        let mut diagnostic = Diagnostic::error(
            "evidence.policy.unavailable",
            "",
            "the policy file could not be read",
            "Pass the path of a readable regular file.",
        );
        diagnostic.source = Some(registry_platform_yaml::Source {
            file,
            line: None,
            column: None,
        });
        let mut report = Report::new(vec![diagnostic]);
        report.set_files_checked(1);
        return PolicyCheck {
            report,
            unavailable: true,
        };
    };
    let outcome = match kind {
        PolicyKind::Verification => read_verification_policy(&file, &bytes).map(|_| ()),
        PolicyKind::HolderBound => read_holder_bound_policy(&file, &bytes).map(|_| ()),
    };
    let mut report = outcome.err().unwrap_or_else(|| Report::new(Vec::new()));
    report.set_files_checked(1);
    PolicyCheck {
        report,
        unavailable: false,
    }
}

/// Read at most one byte more than the reader's size cap.
fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAXIMUM_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The reader-side shape of one policy document: decoded closed, checked
/// across members, then converted to the verifier's document type.
trait PolicyFile: DeserializeOwned + Serialize {
    fn check(&self, document: &Document) -> Vec<Diagnostic>;
}

fn read<F: PolicyFile, D: DeserializeOwned>(
    file: &str,
    bytes: &[u8],
    format: &FormatSpec<'_>,
) -> Result<D, Report> {
    let mut hook = PolicyExpressions;
    let decoded = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<F>(bytes, &Expect::one(format))?;
    let diagnostics = decoded.value.check(&decoded.document);
    if !diagnostics.is_empty() {
        return Err(Report::new(diagnostics));
    }
    // The verifier's document type is the one wire shape the runtime and the
    // client bindings share, so it is built from what the reader accepted
    // rather than duplicated here. It accepts everything the reader does.
    serde_json::to_value(&decoded.value)
        .and_then(serde_json::from_value)
        .map_err(|_| {
            Report::new(vec![decoded.document.diagnostic_at_value(
                Severity::Error,
                "evidence.policy.not-verifiable",
                "",
                "the verifier refused a policy document the reader accepted",
                "Report this defect with the document's shape, never its values.",
            )])
        })
}

/// A Version 1 verification policy as written.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationPolicyFile {
    expected_assurance_profile: AssuranceProfile,
    issued_by: String,
    provided_by: String,
    requirement: String,
    evidence_type: String,
    purpose: String,
    audience: String,
    configuration_revision: String,
    request_nonce: String,
    expected_subjects: UniqueList<ExpectedSubject>,
    expected_outputs: UniqueList<ExpectedOutput>,
    revoked_key_ids: UniqueList<String>,
    maximum_assertion_lifetime_seconds: AssertionLifetime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    clock_skew_seconds: Option<ClockSkew>,
}

impl PolicyFile for VerificationPolicyFile {
    fn check(&self, document: &Document) -> Vec<Diagnostic> {
        check_expectations(
            document,
            &self.expected_subjects,
            &self.expected_outputs,
            &self.revoked_key_ids,
        )
    }
}

/// A holder-bound verification policy as written.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HolderBoundPolicyFile {
    subject_binding: HolderBoundDeclaration,
    expected_assurance_profile: AssuranceProfile,
    issued_by: String,
    provided_by: String,
    requirement: String,
    evidence_type: String,
    expected_issuance_purpose: String,
    configuration_revision: String,
    expected_subjects: UniqueList<ExpectedSubject>,
    expected_outputs: UniqueList<ExpectedOutput>,
    revoked_key_ids: UniqueList<String>,
    maximum_assertion_lifetime_seconds: AssertionLifetime,
    key_binding_audience: String,
    key_binding_nonce: String,
    maximum_key_binding_age_seconds: KeyBindingAge,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    clock_skew_seconds: Option<ClockSkew>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_holder_key_thumbprint: Option<String>,
}

impl PolicyFile for HolderBoundPolicyFile {
    fn check(&self, document: &Document) -> Vec<Diagnostic> {
        check_expectations(
            document,
            &self.expected_subjects,
            &self.expected_outputs,
            &self.revoked_key_ids,
        )
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedSubject {
    role: String,
    binding: String,
}

/// One expected output. `handle` and `required` may be omitted by a stored
/// legacy procedure; the verifier supplies the same defaults it always has.
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedOutput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
    concept: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    required: Option<bool>,
    form: ExpectedForm,
}

/// A scalar form is written as a plain string and the list form as a
/// mapping under `list`, so the two differ by node kind.
#[derive(PartialEq, Eq, Hash)]
enum ExpectedForm {
    Scalar(ScalarForm),
    List(ListFormWrapper),
}

shape_union!(ExpectedForm {
    scalar => Scalar,
    mapping => List,
});

impl Serialize for ExpectedForm {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Scalar(form) => form.serialize(serializer),
            Self::List(form) => form.serialize(serializer),
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
enum ScalarForm {
    Boolean,
    Integer,
    String,
    DateBucket,
    TimeBucket,
    EntityReference,
    Structured,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
struct ListFormWrapper {
    list: ListForm,
}

/// A list form. `items` and `unique` are written together, or both omitted
/// by a stored legacy procedure.
#[derive(Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListForm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    items: Option<ListItemForm>,
    minimum_items: ListItems,
    maximum_items: ListItems,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unique: Option<bool>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
enum ListItemForm {
    String,
    EntityReference,
}

/// The rules that span members: how many subjects, outputs, and revoked
/// keys a policy pins, that a list form writes `items` and `unique`
/// together, that `unique` is true, and that its bounds are not inverted.
fn check_expectations(
    document: &Document,
    subjects: &[ExpectedSubject],
    outputs: &[ExpectedOutput],
    revoked_key_ids: &[String],
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let mut count =
        |pointer: &str, length: usize, minimum: usize, maximum: usize, message: &str| {
            if !(minimum..=maximum).contains(&length) {
                diagnostics.push(document.diagnostic_at_value(
                Severity::Error,
                "evidence.policy.invalid-count",
                pointer,
                message,
                "Pin only what the original transaction accepted, within the contract's bounds.",
            ));
            }
        };
    count(
        "/expectedSubjects",
        subjects.len(),
        1,
        MAXIMUM_EXPECTED_SUBJECTS,
        "expectedSubjects pins 1 to 8 subjects",
    );
    count(
        "/expectedOutputs",
        outputs.len(),
        1,
        MAXIMUM_EXPECTED_OUTPUTS,
        "expectedOutputs pins 1 to 16 outputs",
    );
    count(
        "/revokedKeyIds",
        revoked_key_ids.len(),
        0,
        MAXIMUM_REVOKED_KEY_IDS,
        "revokedKeyIds lists at most 33 key ids",
    );
    for (index, output) in outputs.iter().enumerate() {
        if let ExpectedForm::List(wrapper) = &output.form {
            if wrapper.list.items.is_some() != wrapper.list.unique.is_some() {
                diagnostics.push(document.diagnostic_at_value(
                    Severity::Error,
                    "evidence.policy.unpaired-list-form",
                    &format!("/expectedOutputs/{index}/form/list"),
                    "a list form writes items and unique together, or neither",
                    "Write both `items` and `unique`; only a stored legacy procedure omits both.",
                ));
            }
            if wrapper.list.unique == Some(false) {
                diagnostics.push(document.diagnostic_at_value(
                    Severity::Error,
                    "evidence.policy.list-not-unique",
                    &format!("/expectedOutputs/{index}/form/list/unique"),
                    "a list form's items are unique, so unique is true",
                    "Write `unique: true`; the verifier refuses a list that repeats an item.",
                ));
            }
            if wrapper.list.minimum_items.get() > wrapper.list.maximum_items.get() {
                diagnostics.push(document.diagnostic_at_value(
                    Severity::Error,
                    "evidence.policy.list-bounds-inverted",
                    &format!("/expectedOutputs/{index}/form/list/minimumItems"),
                    "minimumItems exceeds maximumItems",
                    "Write a minimumItems that is at most maximumItems.",
                ));
            }
        }
    }
    diagnostics
}

/// A policy states every expectation literally: it is the relying party's
/// own retained state, and a `${...}` expression in it would stand for a
/// value no reviewer saw.
struct PolicyExpressions;

impl PolicyExpressions {
    fn check(text: &str) -> Result<(), Refusal> {
        if contains_environment_expression(text) {
            return Err(Refusal {
                code: "config.substitution-not-allowed".to_owned(),
                message: "a `${...}` expression is written in a verification policy, \
                          which states every expectation literally"
                    .to_owned(),
                suggested_action: "Write the value in the policy directly.".to_owned(),
            });
        }
        Ok(())
    }
}

impl ScalarHook for PolicyExpressions {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        Self::check(site.text)
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Self::check(site.text).map(|()| None)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use super::*;

    const REVISION: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const CANARY: &str = "canary-7f3a";

    fn verification_policy() -> String {
        format!(
            "expectedAssuranceProfile: evidence-grade
issuedBy: https://evidence.example.test
providedBy: https://registry.example.test
requirement: https://registry.example.test/requirements/adult-status
evidenceType: https://registry.example.test/evidence/adult-status
purpose: benefit.eligibility
audience: https://relying.example.test
configurationRevision: {REVISION}
requestNonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
expectedSubjects:
  - {{role: subject, binding: urn:evidence:subject:v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}}
expectedOutputs:
  - handle: adult
    concept: https://registry.example.test/concepts/adult
    required: true
    form: boolean
  - handle: regions
    concept: https://registry.example.test/concepts/regions
    required: false
    form: {{list: {{items: string, minimumItems: 1, maximumItems: 4, unique: true}}}}
revokedKeyIds: []
maximumAssertionLifetimeSeconds: 3600
"
        )
    }

    fn holder_bound_policy() -> String {
        verification_policy()
            .replace("purpose:", "expectedIssuancePurpose:")
            .replace("audience: https://relying.example.test\n", "")
            .replace(
                "requestNonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
                "keyBindingAudience: https://relying.example.test\n\
                 keyBindingNonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                 maximumKeyBindingAgeSeconds: 60\n",
            )
            .replacen(
                "expectedAssuranceProfile",
                "subjectBinding: holder-bound\nexpectedAssuranceProfile",
                1,
            )
    }

    #[test]
    fn reads_both_documents_into_the_verifier_types() {
        let policy = read_verification_policy("policy.yaml", verification_policy().as_bytes())
            .expect("the Version 1 policy reads");
        assert_eq!(policy.expected_outputs.len(), 2);
        assert_eq!(policy.clock_skew_seconds, 0);
        let holder_bound =
            read_holder_bound_policy("policy.yaml", holder_bound_policy().as_bytes())
                .expect("the holder-bound policy reads");
        assert_eq!(holder_bound.maximum_key_binding_age_seconds, 60);
    }

    #[test]
    fn a_stored_legacy_procedure_keeps_the_verifier_defaults() {
        let legacy = verification_policy()
            .replace("  - handle: adult\n    concept:", "  - concept:")
            .replace("    required: true\n", "")
            .replace("items: string, ", "")
            .replace(", unique: true", "");
        let policy = read_verification_policy("policy.yaml", legacy.as_bytes())
            .expect("the legacy policy reads");
        let output = &policy.expected_outputs[0];
        assert!(output.handle.starts_with("concept-"));
        assert!(output.required);
    }

    #[test]
    fn neither_document_reads_as_the_other() {
        assert!(read_holder_bound_policy("policy.yaml", verification_policy().as_bytes()).is_err());
        assert!(read_verification_policy("policy.yaml", holder_bound_policy().as_bytes()).is_err());
    }

    #[test]
    fn refuses_each_rule_at_its_member_without_the_value() {
        let base = verification_policy();
        let subject = "  - {role: subject, binding: urn:evidence:subject:v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}\n";
        let cases: Vec<(&str, String, &str, &str, usize)> = vec![
            (
                "unknown member",
                format!("{base}{CANARY}: true\n"),
                "config.unknown-key",
                "/canary-7f3a",
                23,
            ),
            (
                "lifetime out of range",
                base.replace("Seconds: 3600", "Seconds: 0"),
                "config.out-of-range",
                "/maximumAssertionLifetimeSeconds",
                22,
            ),
            (
                "clock skew out of range",
                format!("{base}clockSkewSeconds: 301\n"),
                "config.out-of-range",
                "/clockSkewSeconds",
                23,
            ),
            (
                "list bound out of range",
                base.replace("maximumItems: 4", "maximumItems: 65"),
                "config.out-of-range",
                "/expectedOutputs/1/form/list/maximumItems",
                20,
            ),
            (
                "unknown form",
                base.replace("form: boolean", &format!("form: {CANARY}")),
                "config.unknown-variant",
                "/expectedOutputs/0/form",
                16,
            ),
            (
                "repeated subject",
                base.replace(subject, &format!("{subject}{subject}")),
                "config.duplicate-item",
                "/expectedSubjects/1",
                12,
            ),
            (
                "no subject",
                base.replace(
                    &format!("expectedSubjects:\n{subject}"),
                    "expectedSubjects: []\n",
                ),
                "evidence.policy.invalid-count",
                "/expectedSubjects",
                10,
            ),
            (
                "unpaired list form",
                base.replace(", unique: true", ""),
                "evidence.policy.unpaired-list-form",
                "/expectedOutputs/1/form/list",
                20,
            ),
            (
                "list that is not unique",
                base.replace("unique: true", "unique: false"),
                "evidence.policy.list-not-unique",
                "/expectedOutputs/1/form/list/unique",
                20,
            ),
            (
                "inverted list bounds",
                base.replace(
                    "minimumItems: 1, maximumItems: 4",
                    "minimumItems: 5, maximumItems: 4",
                ),
                "evidence.policy.list-bounds-inverted",
                "/expectedOutputs/1/form/list/minimumItems",
                20,
            ),
            (
                "substitution",
                base.replace("purpose: benefit.eligibility", "purpose: ${PURPOSE}"),
                "config.substitution-not-allowed",
                "/purpose",
                6,
            ),
        ];
        for (label, text, code, path, line) in cases {
            let report = read_verification_policy("policy.yaml", text.as_bytes()).expect_err(label);
            let diagnostic = &report.diagnostics()[0];
            assert_eq!(diagnostic.code, code, "{label}");
            assert_eq!(diagnostic.path, path, "{label}");
            let source = diagnostic.source.as_ref().expect("a positioned diagnostic");
            assert_eq!(source.line, Some(line), "{label}");
            let rendered = report.render_human();
            assert!(!rendered.contains("AAAAAAAA"), "{label}: {rendered}");
            assert!(!rendered.contains(REVISION), "{label}");
        }
    }

    /// The examples the format registry names are read as the verify
    /// commands read them, and satisfy the frozen contracts.
    #[test]
    fn the_registered_examples_read_and_satisfy_the_contracts() {
        let cases: [(&[u8], &[u8], PolicyKind); 2] = [
            (
                include_bytes!("../../../products/evidence/examples/verification.policy.yaml"),
                include_bytes!("../../../products/evidence/contracts/verification-policy.schema.yaml"),
                PolicyKind::Verification,
            ),
            (
                include_bytes!("../../../products/evidence/examples/holder-bound.policy.yaml"),
                include_bytes!(
                    "../../../products/evidence/contracts/holder-bound-verification-policy.schema.yaml"
                ),
                PolicyKind::HolderBound,
            ),
        ];
        for (example, contract, kind) in cases {
            let read = match kind {
                PolicyKind::Verification => {
                    read_verification_policy("example", example).map(|_| ())
                }
                PolicyKind::HolderBound => read_holder_bound_policy("example", example).map(|_| ()),
            };
            if let Err(report) = read {
                panic!(
                    "the {kind:?} example is refused:\n{}",
                    report.render_human()
                );
            }
            let contract: serde_json::Value =
                serde_norway::from_slice(contract).expect("the contract is YAML");
            let instance: serde_json::Value =
                serde_norway::from_slice(example).expect("the example is YAML");
            let compiled = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .should_validate_formats(true)
                .compile(&contract)
                .expect("the contract compiles");
            assert!(
                compiled.is_valid(&instance),
                "the {kind:?} example does not satisfy its contract"
            );
        }
    }

    #[test]
    fn a_check_of_an_unreadable_file_is_unavailable() {
        let missing = Path::new("/nonexistent/evidence/policy.yaml");
        let check = check_policy(missing, PolicyKind::Verification);
        assert!(check.unavailable);
        assert_eq!(
            check.report.diagnostics()[0].code,
            "evidence.policy.unavailable"
        );
    }
}
