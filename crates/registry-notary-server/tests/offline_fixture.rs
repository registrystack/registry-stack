// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "registry-notary-cel")]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use registry_notary_core::{EvaluateRequest, StandaloneRegistryNotaryConfig};
use registry_notary_server::cel_worker::{CelWorkerConfig, CelWorkerLimits};
use registry_notary_server::standalone::{
    OfflineAuthentication, OfflineNotaryErrorClass, OfflineNotaryHarness,
    OfflineNotaryHarnessError, OfflineNotaryRequest, OfflineRelayConsultation, OfflineRelayOutcome,
};
use serde_json::{json, Value};

const CONTRACT_HASH: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_CONTRACT_HASH: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn config() -> StandaloneRegistryNotaryConfig {
    serde_norway::from_str(
        r#"
evidence:
  enabled: true
  service_id: offline-notary-test
  allowed_purposes: [benefit-verification, other-verification]
  variables:
    as_of_date: { from: request.variables.as_of_date, type: date }
  relay:
    base_url: https://relay.internal.example
    workload_client_id: registry-notary
    token_file: /run/secrets/registry-notary-relay.jwt
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: OFFLINE_UNUSED_ISSUER_KEY
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
  claims:
    - id: record-exists
      title: Record exists
      version: "1"
      subject_type: person
      evidence_mode: &person_evidence
        type: registry_backed
        consultations:
          enrollment:
            profile: &person_profile
              id: example.person.exact
              contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            inputs: { subject_id: target.id }
            outputs: &person_outputs
              active: { type: boolean, nullable: true }
              birth_date: { type: date, nullable: true }
              category: { type: string, nullable: true, max_bytes: 32 }
      value: { type: boolean, nullable: false }
      purpose: benefit-verification
      required_scopes: [registry:person:read]
      rule: { type: exists, source: enrollment }
      formats: &formats [application/vnd.registry-notary.claim-result+json]
      disclosure: &disclosure
        default: value
        allowed: [value, predicate, redacted]
        downgrade: deny
    - id: active
      title: Active
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile: *person_profile
            inputs: { subject_id: target.id }
            outputs: *person_outputs
      value: { type: boolean, nullable: true }
      purpose: benefit-verification
      required_scopes: [registry:person:read]
      rule: { type: extract, source: enrollment, field: active }
      formats: *formats
      disclosure: *disclosure
    - id: birth-date
      title: Birth date
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile: *person_profile
            inputs: { subject_id: target.id }
            outputs: *person_outputs
      value: { type: date, nullable: true }
      purpose: benefit-verification
      required_scopes: [registry:person:read]
      rule: { type: extract, source: enrollment, field: birth_date }
      formats: *formats
      disclosure: *disclosure
    - id: category
      title: Category
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile: *person_profile
            inputs: { subject_id: target.id }
            outputs: *person_outputs
      value: { type: string, nullable: true }
      purpose: benefit-verification
      required_scopes: [registry:person:read]
      rule: { type: extract, source: enrollment, field: category }
      formats: *formats
      disclosure: *disclosure
    - id: eligible
      title: Eligible
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile: *person_profile
            inputs: { subject_id: target.id }
            outputs: *person_outputs
      value: { type: boolean, nullable: false }
      purpose: benefit-verification
      required_scopes: [registry:person:read]
      rule:
        type: cel
        expression: enrollment.matched
      formats: *formats
      disclosure: *disclosure
    - id: age-years
      title: Age years
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile: *person_profile
            inputs: { subject_id: target.id }
            outputs: *person_outputs
      value: { type: integer, nullable: true }
      purpose: benefit-verification
      required_scopes: [registry:person:read]
      rule:
        type: cel
        expression: >-
          enrollment.matched && enrollment.birth_date != null
            ? date.age_on(enrollment.birth_date, as_of_date)
            : null
      formats: *formats
      disclosure: *disclosure
    - id: other-status
      title: Other status
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          other:
            profile:
              id: example.other.exact
              contract_hash: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            inputs: { subject_id: target.id }
            outputs:
              status: { type: string, nullable: true, max_bytes: 16 }
      value: { type: string, nullable: true }
      purpose: other-verification
      required_scopes: [registry:other:read]
      rule: { type: extract, source: other, field: status }
      formats: *formats
      disclosure: *disclosure
auth:
  mode: api_key
  api_keys:
    - id: authoring-test-principal
      fingerprint:
        provider: env
        name: OFFLINE_UNUSED_API_KEY_HASH
      scopes: [registry:person:read, registry:other:read]
"#,
    )
    .expect("offline Notary config parses")
}

fn cel_worker_bin() -> PathBuf {
    let env_path = PathBuf::from(env!("CARGO_BIN_EXE_registry-notary-cel-worker"));
    if env_path
        .parent()
        .and_then(|parent| parent.file_name())
        .is_some_and(|file_name| file_name == "deps")
    {
        let candidate = env_path
            .parent()
            .and_then(|parent| parent.parent())
            .expect("target debug dir")
            .join("registry-notary-cel-worker");
        if candidate.is_file() {
            return candidate;
        }
    }
    env_path
}

fn worker_config() -> CelWorkerConfig {
    CelWorkerConfig {
        command: cel_worker_bin(),
        command_args: Vec::new(),
        command_envs: Vec::new(),
        current_dir: None,
        forbidden_env_names: BTreeSet::from([
            OsString::from("REGISTRY_NOTARY_AUDIT_HASH_SECRET"),
            OsString::from("OFFLINE_UNUSED_API_KEY_HASH"),
            OsString::from("OFFLINE_UNUSED_ISSUER_KEY"),
        ]),
        max_workers: 1,
        request_timeout: Duration::from_secs(5),
        max_request_bytes: 64 * 1024,
        max_response_bytes: 16 * 1024,
        max_stderr_bytes: 1024,
        max_memory_bytes: None,
        allow_regex: false,
        limits: CelWorkerLimits::default(),
    }
}

fn relay(
    profile_id: &str,
    contract_hash: &str,
    purpose: &str,
    input: &str,
    outcome: OfflineRelayOutcome,
    outputs: BTreeMap<String, Value>,
) -> OfflineRelayConsultation {
    OfflineRelayConsultation::decoded(
        profile_id,
        contract_hash,
        purpose,
        "subject_id",
        input,
        outcome,
        outputs,
    )
}

fn person_relay(
    input: &str,
    outcome: OfflineRelayOutcome,
    outputs: BTreeMap<String, Value>,
) -> OfflineRelayConsultation {
    relay(
        "example.person.exact",
        CONTRACT_HASH,
        "benefit-verification",
        input,
        outcome,
        outputs,
    )
}

fn harness() -> OfflineNotaryHarness {
    OfflineNotaryHarness::compile(
        config(),
        vec![
            person_relay(
                "person-1",
                OfflineRelayOutcome::Match,
                BTreeMap::from([
                    ("active".to_string(), json!(true)),
                    ("birth_date".to_string(), json!("2000-02-29")),
                    ("category".to_string(), Value::Null),
                ]),
            ),
            person_relay("person-none", OfflineRelayOutcome::NoMatch, BTreeMap::new()),
            person_relay(
                "person-ambiguous",
                OfflineRelayOutcome::Ambiguous,
                BTreeMap::new(),
            ),
            relay(
                "example.other.exact",
                OTHER_CONTRACT_HASH,
                "other-verification",
                "person-2",
                OfflineRelayOutcome::Match,
                BTreeMap::from([("status".to_string(), json!("CURRENT"))]),
            ),
        ],
        worker_config(),
    )
    .expect("offline harness compiles")
}

fn request(input: Option<&str>, claims: &[&str], purpose: &str) -> EvaluateRequest {
    let target = input.map_or_else(
        || json!({"type": "person"}),
        |input| json!({"type": "person", "id": input}),
    );
    serde_json::from_value(json!({
        "target": target,
        "claims": claims,
        "disclosure": "value",
        "purpose": purpose,
    }))
    .expect("evaluation request parses")
}

fn claim_value<'a>(
    evidence: &'a registry_notary_server::standalone::OfflineNotaryEvidence,
    claim_id: &str,
) -> Option<&'a Value> {
    evidence
        .claims()
        .iter()
        .find(|claim| claim.claim_id() == claim_id)
        .and_then(|claim| claim.value())
}

#[tokio::test]
async fn composite_consultation_fixture_binds_the_complete_input_map() {
    let mut configured = config();
    for claim in &mut configured.evidence.claims {
        let registry_notary_core::ClaimEvidenceMode::RegistryBacked { consultations } =
            &mut claim.evidence_mode
        else {
            continue;
        };
        let Some(consultation) = consultations.get_mut("enrollment") else {
            continue;
        };
        consultation.inputs.insert(
            "country_code".to_string(),
            registry_notary_core::RelayConsultationInput::TargetIdentifier(
                "request.target.identifiers.country_code".to_string(),
            ),
        );
    }
    let fixture = OfflineRelayConsultation::decoded_inputs(
        "example.person.exact",
        CONTRACT_HASH,
        "benefit-verification",
        BTreeMap::from([
            ("country_code".to_string(), "TH".to_string()),
            ("subject_id".to_string(), "person-1".to_string()),
        ]),
        OfflineRelayOutcome::Match,
        BTreeMap::from([
            ("active".to_string(), json!(true)),
            ("birth_date".to_string(), json!("2000-02-29")),
            ("category".to_string(), Value::Null),
        ]),
    );
    let debug = format!("{fixture:?}");
    assert!(debug.contains("country_code"));
    assert!(!debug.contains("person-1"));
    assert!(!debug.contains("TH"));
    let harness = OfflineNotaryHarness::compile(configured, vec![fixture], worker_config())
        .expect("composite offline harness compiles");
    let evaluation: EvaluateRequest = serde_json::from_value(json!({
        "target": {
            "type": "person",
            "id": "person-1",
            "identifiers": [{"scheme": "country_code", "value": "TH"}]
        },
        "claims": ["active"],
        "disclosure": "value",
        "purpose": "benefit-verification"
    }))
    .expect("composite evaluation request parses");

    let evidence = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            evaluation,
        ))
        .await;

    assert_eq!(evidence.error_class(), None, "{evidence:?}");
    assert_eq!(claim_value(&evidence, "active"), Some(&json!(true)));
    assert_eq!(evidence.relay_calls(), 1);
    assert_eq!(evidence.direct_source_calls(), 0);
}

#[tokio::test]
async fn production_runtime_evaluates_extract_exists_cel_date_nullable_and_reuses_consultation() {
    let mut evaluation = request(
        Some("person-1"),
        &[
            "record-exists",
            "active",
            "birth-date",
            "category",
            "eligible",
        ],
        "benefit-verification",
    );
    evaluation.variables = registry_notary_core::RequestVariables::try_new(BTreeMap::from([(
        "as_of_date".to_string(),
        "2026-01-01".to_string(),
    )]))
    .expect("date request variable is bounded");
    let harness = harness();
    let evidence = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            evaluation,
        ))
        .await;

    assert_eq!(evidence.error_class(), None, "{evidence:?}");
    assert_eq!(evidence.relay_calls(), 1);
    assert_eq!(evidence.direct_source_calls(), 0);
    assert_eq!(evidence.consultation_count(), 1);
    assert_eq!(claim_value(&evidence, "record-exists"), Some(&json!(true)));
    assert_eq!(claim_value(&evidence, "active"), Some(&json!(true)));
    assert_eq!(
        claim_value(&evidence, "birth-date"),
        Some(&json!("2000-02-29"))
    );
    assert_eq!(claim_value(&evidence, "category"), Some(&Value::Null));
    assert_eq!(claim_value(&evidence, "eligible"), Some(&json!(true)));
}

#[tokio::test]
async fn guarded_date_age_policy_receives_compiled_request_variable_after_relay() {
    let configured = config();
    let configured_expression = configured
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "age-years")
        .and_then(|claim| match &claim.rule {
            registry_notary_core::RuleConfig::Cel { expression, .. } => Some(expression.as_str()),
            _ => None,
        })
        .expect("age policy is configured as CEL");
    assert!(configured_expression.contains('\n'));
    let direct = registry_notary_server::cel_worker::CelWorker::lazy(worker_config())
        .evaluate(
            configured_expression,
            json!({
                "enrollment": {
                    "matched": true,
                    "outcome": "match",
                    "active": true,
                    "birth_date": "2000-02-29",
                    "category": null,
                },
                "as_of_date": "2026-01-01",
            }),
        )
        .await;
    assert_eq!(direct.expect("direct worker policy evaluates"), json!(25));
    let mut evaluation = request(Some("person-1"), &["age-years"], "benefit-verification");
    evaluation.variables = registry_notary_core::RequestVariables::try_new(BTreeMap::from([(
        "as_of_date".to_string(),
        "2026-01-01".to_string(),
    )]))
    .expect("date request variable is bounded");
    let harness = harness();
    let evidence = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            evaluation,
        ))
        .await;

    assert_eq!(evidence.error_class(), None, "{evidence:?}");
    assert_eq!(claim_value(&evidence, "age-years"), Some(&json!(25)));
    assert_eq!(evidence.relay_calls(), 1);
    assert_eq!(evidence.direct_source_calls(), 0);

    let mut absent_evaluation =
        request(Some("person-none"), &["age-years"], "benefit-verification");
    absent_evaluation.variables = registry_notary_core::RequestVariables::try_new(BTreeMap::from(
        [("as_of_date".to_string(), "2026-01-01".to_string())],
    ))
    .expect("date request variable is bounded");
    let absent = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            absent_evaluation,
        ))
        .await;
    assert_eq!(absent.error_class(), None, "{absent:?}");
    assert_eq!(claim_value(&absent, "age-years"), Some(&Value::Null));
    assert_eq!(absent.relay_calls(), 1);
    assert_eq!(absent.direct_source_calls(), 0);
}

#[tokio::test]
async fn authentication_scope_purpose_and_input_denials_are_before_all_source_access() {
    let harness = harness();
    for authentication in [
        OfflineAuthentication::Missing,
        OfflineAuthentication::WrongCredential,
        OfflineAuthentication::InsufficientScope,
    ] {
        let evidence = harness
            .evaluate(OfflineNotaryRequest::new(
                authentication,
                request(Some("person-1"), &["active"], "benefit-verification"),
            ))
            .await;
        assert_eq!(
            evidence.error_class(),
            Some(OfflineNotaryErrorClass::AuthorizationDenied),
            "{evidence:?}"
        );
        assert_eq!(evidence.relay_calls(), 0);
        assert_eq!(evidence.direct_source_calls(), 0);
    }

    let wrong_purpose = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            request(Some("person-1"), &["active"], "unrelated-purpose"),
        ))
        .await;
    assert_eq!(
        wrong_purpose.error_class(),
        Some(OfflineNotaryErrorClass::PurposeDenied)
    );
    assert_eq!(wrong_purpose.relay_calls(), 0);
    assert_eq!(wrong_purpose.direct_source_calls(), 0);

    let malformed = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            request(None, &["active"], "benefit-verification"),
        ))
        .await;
    assert_eq!(
        malformed.error_class(),
        Some(OfflineNotaryErrorClass::InvalidInput)
    );
    assert_eq!(malformed.relay_calls(), 0);
    assert_eq!(malformed.direct_source_calls(), 0);

    let mut forbidden_disclosure_request =
        request(Some("person-1"), &["active"], "benefit-verification");
    forbidden_disclosure_request.disclosure = Some("unsupported".to_string());
    let forbidden_disclosure = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            forbidden_disclosure_request,
        ))
        .await;
    assert_eq!(
        forbidden_disclosure.error_class(),
        Some(OfflineNotaryErrorClass::InvalidInput)
    );
    assert_eq!(forbidden_disclosure.relay_calls(), 0);
    assert_eq!(forbidden_disclosure.direct_source_calls(), 0);
}

#[tokio::test]
async fn exact_profiles_are_isolated_and_missing_input_or_ambiguous_results_fail_closed() {
    let harness = harness();
    let other = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            request(Some("person-2"), &["other-status"], "other-verification"),
        ))
        .await;
    assert_eq!(other.error_class(), None, "{other:?}");
    assert_eq!(claim_value(&other, "other-status"), Some(&json!("CURRENT")));
    assert_eq!(other.relay_calls(), 1);
    assert_eq!(other.direct_source_calls(), 0);

    let missing_exact_input = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            request(
                Some("person-not-installed"),
                &["active"],
                "benefit-verification",
            ),
        ))
        .await;
    assert_eq!(
        missing_exact_input.error_class(),
        Some(OfflineNotaryErrorClass::InvalidInput)
    );
    assert_eq!(missing_exact_input.relay_calls(), 0);
    assert_eq!(missing_exact_input.direct_source_calls(), 0);

    let ambiguous = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            request(
                Some("person-ambiguous"),
                &["active"],
                "benefit-verification",
            ),
        ))
        .await;
    assert_eq!(
        ambiguous.error_class(),
        Some(OfflineNotaryErrorClass::Ambiguous)
    );
    assert_eq!(ambiguous.relay_calls(), 1);
    assert_eq!(ambiguous.direct_source_calls(), 0);
}

#[tokio::test]
async fn no_match_nullable_and_redacted_disclosure_use_production_views() {
    let harness = harness();
    let absent = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            request(
                Some("person-none"),
                &["record-exists", "category"],
                "benefit-verification",
            ),
        ))
        .await;
    assert_eq!(absent.error_class(), None, "{absent:?}");
    assert_eq!(claim_value(&absent, "record-exists"), Some(&json!(false)));
    assert_eq!(claim_value(&absent, "category"), Some(&Value::Null));
    assert_eq!(absent.relay_calls(), 1);
    assert_eq!(absent.consultation_count(), 1);

    let mut redacted_request = request(Some("person-1"), &["birth-date"], "benefit-verification");
    redacted_request.disclosure = Some("redacted".to_string());
    let redacted = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            redacted_request,
        ))
        .await;
    assert_eq!(redacted.error_class(), None, "{redacted:?}");
    assert_eq!(redacted.claims()[0].value(), None);
    assert_eq!(redacted.claims()[0].disclosure(), "redacted");
    assert_eq!(
        redacted.claims()[0].redacted_fields(),
        &["birth-date".to_string()]
    );
    assert_eq!(redacted.direct_source_calls(), 0);

    let mut predicate_request = request(Some("person-1"), &["active"], "benefit-verification");
    predicate_request.disclosure = Some("predicate".to_string());
    let predicate = harness
        .evaluate(OfflineNotaryRequest::new(
            OfflineAuthentication::Valid,
            predicate_request,
        ))
        .await;
    assert_eq!(predicate.error_class(), None, "{predicate:?}");
    assert_eq!(predicate.claims()[0].value(), Some(&json!(true)));
    assert_eq!(predicate.claims()[0].satisfied(), Some(true));
    assert_eq!(predicate.claims()[0].disclosure(), "predicate");
    assert_eq!(predicate.direct_source_calls(), 0);
}

#[test]
fn decoder_evidence_must_bind_to_a_compiled_profile_contract() {
    let result = OfflineNotaryHarness::compile(
        config(),
        vec![person_relay(
            "person-1",
            OfflineRelayOutcome::Match,
            BTreeMap::from([
                ("active".to_string(), json!(true)),
                ("birth_date".to_string(), json!("2000-02-29")),
                ("category".to_string(), json!("CURRENT")),
            ]),
        )],
        worker_config(),
    );
    assert!(result.is_ok());

    let wrong_contract = OfflineNotaryHarness::compile(
        config(),
        vec![relay(
            "example.person.exact",
            OTHER_CONTRACT_HASH,
            "benefit-verification",
            "person-1",
            OfflineRelayOutcome::Match,
            BTreeMap::from([
                ("active".to_string(), json!(true)),
                ("birth_date".to_string(), json!("2000-02-29")),
                ("category".to_string(), json!("CURRENT")),
            ]),
        )],
        worker_config(),
    );
    assert!(matches!(
        wrong_contract,
        Err(OfflineNotaryHarnessError::InvalidRelayEvidence)
    ));
}
