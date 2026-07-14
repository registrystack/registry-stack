use super::root::{
    expect_self_attestation_error, minimal_claim, valid_delegated_self_attestation_config,
    valid_self_attestation_config,
};
use super::support::minimal_config;
use super::*;

const CONTRACT_HASH: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn relay_connection() -> RelayConnectionConfig {
    serde_norway::from_str(
        r#"
base_url: https://relay.internal.example
workload_client_id: registry-notary
token_file: /run/secrets/registry-notary-relay.jwt
"#,
    )
    .expect("Relay connection parses")
}

fn registry_mode(consultation_name: &str) -> ClaimEvidenceMode {
    ClaimEvidenceMode::RegistryBacked {
        consultations: std::collections::BTreeMap::from([(
            consultation_name.to_string(),
            RelayConsultationConfig {
                profile: RelayConsultationProfileRef {
                    id: "example.person-status.exact".to_string(),
                    contract_hash: CONTRACT_HASH.to_string(),
                },
                inputs: std::collections::BTreeMap::from([(
                    "subject_id".to_string(),
                    RelayConsultationInput::TargetId,
                )]),
                outputs: std::collections::BTreeMap::from([(
                    "registration_status".to_string(),
                    RelayOutputContract::String {
                        nullable: true,
                        max_bytes: 64,
                    },
                )]),
            },
        )]),
    }
}

fn make_registry_backed(claim: &mut ClaimDefinition, consultation_name: &str) {
    claim.evidence_mode = registry_mode(consultation_name);
    claim.purpose = Some("benefit-verification".to_string());
    claim.required_scopes = vec!["registry:consult:person-status".to_string()];
    claim.value.value_type = "string".to_string();
    claim.value.nullable = true;
    claim.rule = RuleConfig::ConsultationOutput {
        consultation: consultation_name.to_string(),
        output: "registration_status".to_string(),
    };
}

fn valid_registry_backed_config() -> StandaloneRegistryNotaryConfig {
    let mut config = minimal_config();
    config.evidence.relay = Some(relay_connection());
    let mut claim = minimal_claim("person-status-known");
    make_registry_backed(&mut claim, "person_status");
    config.evidence.claims.push(claim);
    config
}

fn expect_mode_error(config: &StandaloneRegistryNotaryConfig, expected: &str) {
    let error = config
        .validate()
        .expect_err("invalid claim evidence mode must fail validation");
    assert!(
        matches!(
            error,
            EvidenceConfigError::InvalidClaimEvidenceMode { ref reason, .. }
                if reason.contains(expected)
        ),
        "unexpected error: {error:?}"
    );
}

fn expect_self_attestation_closure_error(config: &StandaloneRegistryNotaryConfig) {
    let error = config
        .validate()
        .expect_err("a self-attestation closure with mixed evidence modes must fail validation");
    assert!(
        matches!(
            error,
            EvidenceConfigError::InvalidClaimEvidenceMode { ref reason, .. }
                if reason.contains("self_attested dependency closure")
                    || reason.contains("cannot declare depends_on")
        ) || matches!(
            error,
            EvidenceConfigError::InvalidSelfAttestationConfig { ref reason }
                if reason.contains("cannot include registry_backed claim")
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn consultation_rules_reject_removed_source_named_variants() {
    let output: RuleConfig = serde_norway::from_str(
        r#"
type: consultation_output
consultation: person_status
output: registration_status
"#,
    )
    .expect("consultation output rule parses");
    assert!(matches!(output, RuleConfig::ConsultationOutput { .. }));

    let matched: RuleConfig = serde_norway::from_str(
        r#"
type: consultation_matched
consultation: person_status
"#,
    )
    .expect("consultation matched rule parses");
    assert!(matches!(matched, RuleConfig::ConsultationMatched { .. }));

    for removed in [
        "type: extract\nsource: person_status\nfield: registration_status\n",
        "type: exists\nsource: person_status\n",
    ] {
        serde_norway::from_str::<RuleConfig>(removed)
            .expect_err("unreleased source-named rule variants must not remain aliases");
    }
}

#[test]
fn claim_evidence_mode_is_required_and_closed() {
    let missing = serde_norway::from_str::<ClaimDefinition>(
        r#"
id: source-free
title: Source free
version: "1"
subject_type: person
rule:
  type: cel
  expression: "true"
"#,
    )
    .expect_err("missing evidence_mode must fail deserialization");
    assert!(missing.to_string().contains("evidence_mode"));

    serde_norway::from_str::<ClaimDefinition>(
        r#"
id: unknown-mode
title: Unknown mode
version: "1"
subject_type: person
evidence_mode:
  type: inferred
rule:
  type: cel
  expression: "true"
"#,
    )
    .expect_err("unknown evidence_mode must fail deserialization");

    serde_norway::from_str::<ClaimDefinition>(
        r#"
id: mixed-mode
title: Mixed mode
version: "1"
subject_type: person
evidence_mode:
  type: self_attested
  consultations: {}
rule:
  type: cel
  expression: "true"
"#,
    )
    .expect_err("mode-specific fields cannot be mixed");
}

#[test]
fn consultation_shape_rejects_native_capabilities_and_redacts_bad_target_mapping() {
    serde_norway::from_str::<ClaimDefinition>(
        r#"
id: native-route
title: Native route
version: "1"
subject_type: person
evidence_mode:
  type: registry_backed
  consultations:
    person_status:
      profile:
        id: example.person-status.exact
        contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      inputs:
        subject_id: target.id
      route: /private/person
rule:
  type: consultation_matched
  consultation: person_status
"#,
    )
    .expect_err("native routes must not fit the closed consultation schema");

    let sensitive_target = "actual-person-identifier";
    let error = serde_norway::from_str::<ClaimDefinition>(&format!(
        r#"
id: bad-input
title: Bad input
version: "1"
subject_type: person
evidence_mode:
  type: registry_backed
  consultations:
    person_status:
      profile:
        id: example.person-status.exact
        contract_hash: {CONTRACT_HASH}
      inputs:
        subject_id: {sensitive_target}
rule:
  type: consultation_matched
  consultation: person_status
"#
    ))
    .expect_err("only a closed symbolic target mapping is accepted");
    assert!(!error.to_string().contains(sensitive_target));
}

#[test]
fn consultation_accepts_bounded_named_target_identifiers() {
    let claim: ClaimDefinition = serde_norway::from_str(
        r#"
id: named-identifier
title: Named identifier
version: "1"
subject_type: person
evidence_mode:
  type: registry_backed
  consultations:
    birth_record:
      profile:
        id: example.birth-record.exact
        contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      inputs:
        uin: request.target.identifiers.UIN
purpose: civil-registration-verification
required_scopes: [registry:consult:birth-record]
value:
  type: boolean
rule:
  type: consultation_matched
  consultation: birth_record
"#,
    )
    .expect("named target identifier mapping parses");

    let ClaimEvidenceMode::RegistryBacked { consultations } = claim.evidence_mode else {
        panic!("registry-backed mode")
    };
    let mapping = consultations["birth_record"].inputs["uin"].clone();
    assert_eq!(mapping.request_path(), "request.target.identifiers.UIN");
    assert_eq!(mapping.request_context_path(), "target.identifiers.UIN");
    assert_eq!(
        serde_json::to_value(mapping).expect("mapping serializes"),
        "request.target.identifiers.UIN"
    );

    for invalid in [
        "request.target.identifiers.",
        "request.target.identifiers.1UIN",
        "request.target.identifiers.UIN/other",
        "request.target.identifiers.UIN value",
    ] {
        let yaml = format!(
            r#"
profile:
  id: example.birth-record.exact
  contract_hash: {CONTRACT_HASH}
inputs:
  uin: {invalid}
"#,
        );
        serde_norway::from_str::<RelayConsultationConfig>(&yaml)
            .expect_err("invalid target identifier mapping is rejected");
    }
}

#[test]
fn consultation_accepts_only_closed_requester_identifiers() {
    let consultation: RelayConsultationConfig = serde_norway::from_str(&format!(
        r#"
profile:
  id: example.guardian-link.exact
  contract_hash: {CONTRACT_HASH}
inputs:
  requester_id: request.requester.id
  requester_national_id: request.requester.identifiers.national_id
outputs:
  established: {{ type: boolean, nullable: true }}
"#,
    ))
    .expect("closed requester mappings parse");
    assert!(consultation.inputs["requester_id"].is_requester_derived());
    assert_eq!(
        consultation.inputs["requester_national_id"].request_context_path(),
        "requester.identifiers.national_id"
    );

    for invalid in [
        "requester.id",
        "request.requester.identifiers.",
        "request.requester.identifiers.1national_id",
        "request.requester.attributes.national_id",
    ] {
        let yaml = format!(
            r#"
profile:
  id: example.guardian-link.exact
  contract_hash: {CONTRACT_HASH}
inputs:
  requester: {invalid}
outputs:
  established: {{ type: boolean, nullable: true }}
"#,
        );
        serde_norway::from_str::<RelayConsultationConfig>(&yaml)
            .expect_err("open requester mapping is rejected");
    }
}

#[test]
fn registry_backed_claim_accepts_one_pinned_consultation() {
    let config = valid_registry_backed_config();
    config
        .validate()
        .expect("one pinned Relay consultation validates");

    let serialized =
        serde_json::to_value(&config.evidence.claims[0].evidence_mode).expect("mode serializes");
    assert_eq!(serialized["type"], "registry_backed");
    assert_eq!(
        serialized["consultations"]["person_status"]["inputs"]["subject_id"],
        "target.id"
    );
}

#[test]
fn relay_activation_allows_independent_profiles_purposes_inputs_and_outputs() {
    let mut config = valid_registry_backed_config();
    let mut exists = config.evidence.claims[0].clone();
    exists.id = "person-status-present".to_string();
    exists.title = "Person status known".to_string();
    exists.rule = RuleConfig::ConsultationMatched {
        consultation: "person_status".to_string(),
    };
    exists.value.value_type = "boolean".to_string();
    config.evidence.claims.push(exists);
    config
        .validate()
        .expect("consultation rules may share one pinned consultation");

    let mut exists_only = config.clone();
    exists_only.evidence.claims.remove(0);
    exists_only
        .validate()
        .expect("an exists-only journey retains the declared Relay output contract");

    let mut independent = config.clone();
    let ClaimEvidenceMode::RegistryBacked { consultations } =
        &mut independent.evidence.claims[1].evidence_mode
    else {
        panic!("registry-backed mode")
    };
    let consultation = consultations
        .get_mut("person_status")
        .expect("consultation");
    consultation.profile.id = "example.other-status.exact".to_string();
    consultation.inputs = BTreeMap::from([(
        "uin".to_string(),
        RelayConsultationInput::TargetIdentifier("request.target.identifiers.UIN".to_string()),
    )]);
    consultation.outputs = BTreeMap::from([(
        "other_status".to_string(),
        RelayOutputContract::String {
            nullable: true,
            max_bytes: 64,
        },
    )]);
    independent.evidence.claims[1].purpose = Some("civil-registration-verification".to_string());
    independent.evidence.claims[1].rule = RuleConfig::ConsultationOutput {
        consultation: "person_status".to_string(),
        output: "other_status".to_string(),
    };
    independent.evidence.claims[1].value.value_type = "string".to_string();
    independent
        .validate()
        .expect("independent Relay client identities may coexist");

    let mut different_output = config.clone();
    different_output.evidence.claims[1].rule = RuleConfig::ConsultationOutput {
        consultation: "person_status".to_string(),
        output: "other_status".to_string(),
    };
    different_output.evidence.claims[1].value.value_type = "string".to_string();
    expect_mode_error(
        &different_output,
        "must name a declared consultation output",
    );
}

#[test]
fn registry_backed_consultation_accepts_one_to_sixteen_injective_inputs() {
    let mut config = valid_registry_backed_config();
    let ClaimEvidenceMode::RegistryBacked { consultations } =
        &mut config.evidence.claims[0].evidence_mode
    else {
        panic!("registry-backed mode")
    };
    consultations
        .get_mut("person_status")
        .expect("consultation")
        .inputs = BTreeMap::from([
        ("subject_id".to_string(), RelayConsultationInput::TargetId),
        (
            "birth_date".to_string(),
            RelayConsultationInput::TargetIdentifier(
                "request.target.identifiers.birth_date".to_string(),
            ),
        ),
        (
            "country_code".to_string(),
            RelayConsultationInput::TargetIdentifier(
                "request.target.identifiers.country_code".to_string(),
            ),
        ),
        (
            "registry_id".to_string(),
            RelayConsultationInput::TargetIdentifier(
                "request.target.identifiers.registry_id".to_string(),
            ),
        ),
    ]);
    config.validate().expect("four typed inputs are valid");

    let ClaimEvidenceMode::RegistryBacked { consultations } =
        &mut config.evidence.claims[0].evidence_mode
    else {
        panic!("registry-backed mode")
    };
    let inputs = &mut consultations
        .get_mut("person_status")
        .expect("consultation")
        .inputs;
    for index in 5..=16 {
        inputs.insert(
            format!("input_{index}"),
            RelayConsultationInput::TargetIdentifier(format!(
                "request.target.identifiers.input_{index}"
            )),
        );
    }
    config.validate().expect("sixteen typed inputs are valid");
    let ClaimEvidenceMode::RegistryBacked { consultations } =
        &mut config.evidence.claims[0].evidence_mode
    else {
        panic!("registry-backed mode")
    };
    consultations
        .get_mut("person_status")
        .expect("consultation")
        .inputs
        .insert(
            "input_17".to_string(),
            RelayConsultationInput::TargetIdentifier(
                "request.target.identifiers.input_17".to_string(),
            ),
        );
    expect_mode_error(&config, "one to sixteen");

    let mut duplicate_mapping = valid_registry_backed_config();
    let ClaimEvidenceMode::RegistryBacked { consultations } =
        &mut duplicate_mapping.evidence.claims[0].evidence_mode
    else {
        panic!("registry-backed mode")
    };
    consultations
        .get_mut("person_status")
        .expect("consultation")
        .inputs
        .insert(
            "duplicate_subject".to_string(),
            RelayConsultationInput::TargetId,
        );
    expect_mode_error(&duplicate_mapping, "injectively");
}

#[test]
fn registry_backed_claim_requires_relay_connection() {
    let mut config = valid_registry_backed_config();
    config.evidence.relay = None;
    expect_mode_error(&config, "requires evidence.relay");
}

#[test]
fn registry_backed_claim_enforces_gates_cardinality_and_rule_binding() {
    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].purpose = None;
    expect_mode_error(&config, "explicit bounded purpose token");

    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].required_scopes.clear();
    expect_mode_error(&config, "required_scopes");

    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].operations.batch_evaluate.enabled = true;
    config
        .validate()
        .expect("registry-backed claims may enable the pre-1.0 batch contract");

    let mut config = valid_registry_backed_config();
    let ClaimEvidenceMode::RegistryBacked { consultations } =
        &mut config.evidence.claims[0].evidence_mode
    else {
        panic!("registry-backed mode")
    };
    let duplicate = consultations
        .first_key_value()
        .expect("consultation")
        .1
        .clone();
    consultations.insert("other_status".to_string(), duplicate);
    expect_mode_error(&config, "exactly one named consultation");

    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].rule = RuleConfig::ConsultationMatched {
        consultation: "other_status".to_string(),
    };
    expect_mode_error(&config, "rule.consultation must match");

    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].rule = RuleConfig::Cel {
        expression: "true".to_string(),
        bindings: CelBindingsConfig::default(),
    };
    config
        .validate()
        .expect("registry-backed CEL may evaluate the declared output namespace");
}

#[test]
fn registry_backed_claim_matches_relay_identifier_and_scalar_contract() {
    let mut config = valid_registry_backed_config();
    let ClaimEvidenceMode::RegistryBacked { consultations } =
        &mut config.evidence.claims[0].evidence_mode
    else {
        panic!("registry-backed mode")
    };
    consultations
        .get_mut("person_status")
        .expect("consultation")
        .profile
        .id = "Uppercase.profile".to_string();
    expect_mode_error(&config, "profile.id");

    let mut config = valid_registry_backed_config();
    let ClaimEvidenceMode::RegistryBacked { consultations } =
        &mut config.evidence.claims[0].evidence_mode
    else {
        panic!("registry-backed mode")
    };
    consultations
        .get_mut("person_status")
        .expect("consultation")
        .inputs
        .clear();
    expect_mode_error(&config, "one to sixteen typed request mappings");

    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].rule = RuleConfig::ConsultationMatched {
        consultation: "person_status".to_string(),
    };
    expect_mode_error(
        &config,
        "consultation_matched claim value.type must be boolean",
    );

    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].rule = RuleConfig::ConsultationOutput {
        consultation: "person_status".to_string(),
        output: "nested.status".to_string(),
    };
    config.evidence.claims[0].value.value_type = "string".to_string();
    expect_mode_error(&config, "one top-level Relay output name");

    for unsupported in ["boolean", "integer", "number", "object"] {
        let mut config = valid_registry_backed_config();
        config.evidence.claims[0].rule = RuleConfig::ConsultationOutput {
            consultation: "person_status".to_string(),
            output: "registration_status".to_string(),
        };
        config.evidence.claims[0].value.value_type = unsupported.to_string();
        expect_mode_error(&config, "must match its declared output");
    }
}

#[test]
fn relay_connection_is_single_closed_bounded_and_redacted() {
    let relay: RelayConnectionConfig = serde_norway::from_str(
        r#"
base_url: https://relay.internal.example
workload_client_id: registry-notary
token_file: /run/secrets/private-relay.jwt
allowed_private_cidrs: [10.42.0.0/16, fd42::/64]
"#,
    )
    .expect("Relay connection parses");
    relay.validate().expect("Relay connection validates");
    assert_eq!(relay.allowed_private_cidrs.len(), 2);
    assert_eq!(relay.max_in_flight, 8);
    let debug = format!("{relay:?}");
    assert!(!debug.contains("relay.internal.example"));
    assert!(!debug.contains("private-relay.jwt"));
    assert!(!debug.contains("10.42.0.0/16"));

    serde_norway::from_str::<RelayConnectionConfig>(
        r#"
base_url: https://relay.internal.example
workload_client_id: registry-notary
token_file: /run/secrets/relay.jwt
retry_on_5xx: true
"#,
    )
    .expect_err("retry controls are not part of the closed Relay connection");

    for workload_client_id in ["", "Registry-Notary", "registry:notary"] {
        let mut relay = relay_connection();
        relay.workload_client_id = workload_client_id.to_string();
        assert!(matches!(
            relay.validate(),
            Err(EvidenceConfigError::InvalidRelayConfig { ref reason })
                if reason.contains("workload_client_id")
        ));
    }
}

#[test]
fn relay_token_file_and_private_cidrs_are_exact_and_bounded() {
    relay_connection()
        .validate()
        .expect("target POSIX token path is valid on every configuration host");
    for token_file in [
        PathBuf::from("relative/relay.jwt"),
        PathBuf::from("/run/secrets/../relay.jwt"),
        PathBuf::from("/run/./secrets/relay.jwt"),
        PathBuf::from("//run/secrets/relay.jwt"),
        PathBuf::from("/run/secrets/relay.jwt/"),
        PathBuf::from("/run\\secrets\\relay.jwt"),
        PathBuf::from("C:\\run\\secrets\\relay.jwt"),
        PathBuf::from("/"),
    ] {
        let mut relay = relay_connection();
        relay.token_file = token_file;
        assert!(matches!(
            relay.validate(),
            Err(EvidenceConfigError::InvalidRelayConfig { ref reason })
                if reason.contains("token_file")
        ));
    }

    for cidrs in [
        vec!["10.42.0.1/16"],
        vec!["93.184.216.0/24"],
        vec!["100.100.100.200/32"],
        vec!["fd00:ec2::254/128"],
        vec!["10.42.0.0/16", "10.42.0.0/16"],
    ] {
        let mut relay = relay_connection();
        relay.allowed_private_cidrs = cidrs
            .into_iter()
            .map(|cidr| cidr.parse().expect("test CIDR parses"))
            .collect();
        assert!(matches!(
            relay.validate(),
            Err(EvidenceConfigError::InvalidRelayConfig { ref reason })
                if reason.contains("allowed_private_cidrs")
        ));
    }

    let mut relay = relay_connection();
    relay.allowed_private_cidrs = (0..=16)
        .map(|index| {
            format!("10.{index}.0.0/16")
                .parse()
                .expect("test CIDR parses")
        })
        .collect();
    assert!(matches!(
        relay.validate(),
        Err(EvidenceConfigError::InvalidRelayConfig { ref reason })
            if reason.contains("more than 16")
    ));

    serde_norway::from_str::<RelayConnectionConfig>(
        r#"
base_url: https://relay.internal.example
workload_client_id: registry-notary
token_env: REMOVED_RELAY_TOKEN
"#,
    )
    .expect_err("the removed static environment-token mode is rejected");

    serde_norway::from_str::<RelayConnectionConfig>(
        r#"
base_url: https://relay.internal.example
workload_client_id: registry-notary
token_file: /run/secrets/relay.jwt
token_issuer: REMOVED_DUPLICATE_IDENTITY
"#,
    )
    .expect_err("duplicated local workload-token semantics are rejected");
}

#[test]
fn relay_connection_concurrency_is_operator_bounded() {
    for value in [0, 65] {
        let mut relay = relay_connection();
        relay.max_in_flight = value;
        assert!(matches!(
            relay.validate(),
            Err(EvidenceConfigError::InvalidRelayConfig { ref reason })
                if reason.contains("max_in_flight")
        ));
    }

    let mut relay = relay_connection();
    relay.max_in_flight = 64;
    relay.validate().expect("hard ceiling is accepted");
}

#[test]
fn relay_connection_is_rejected_when_no_registry_backed_claim_uses_it() {
    let mut config = minimal_config();
    config.evidence.relay = Some(relay_connection());
    let error = config
        .validate()
        .expect_err("an unused Relay connection must not be silently accepted");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidRelayConfig { ref reason }
            if reason.contains("at least one registry_backed claim")
    ));
}

#[test]
fn registry_backed_notary_reserves_five_seconds_around_the_service_hop() {
    let mut config = valid_registry_backed_config();
    config.server.request_timeout = Duration::from_secs(29) + Duration::from_millis(999);
    let error = config
        .validate()
        .expect_err("the request timeout must not expire before the Relay service hop");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidRelayConfig { ref reason }
            if reason.contains("at least 30 seconds")
    ));

    config.server.request_timeout = Duration::from_secs(30);
    config
        .validate()
        .expect("the outer request minimum reserves five seconds around the service hop");
}

#[test]
fn relay_connection_requires_https_origin_or_explicit_loopback() {
    let mut config = valid_registry_backed_config();
    let mut relay = relay_connection();
    relay.base_url = "http://relay.internal.example".to_string();
    relay.allow_insecure_localhost = true;
    config.evidence.relay = Some(relay);
    let error = config
        .validate()
        .expect_err("remote HTTP must fail despite localhost escape");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidRelayConfig { .. }
    ));

    let mut config = valid_registry_backed_config();
    let mut relay = relay_connection();
    relay.base_url = "http://127.0.0.1:8080".to_string();
    relay.allow_insecure_localhost = true;
    config.evidence.relay = Some(relay);
    config.deployment.profile = Some(crate::deployment::DeploymentProfile::Local);
    config
        .validate()
        .expect("explicit HTTP loopback is permitted for local development");
    assert!(config.gate_input().relay_insecure_url);

    let mut config = valid_registry_backed_config();
    let mut relay = relay_connection();
    relay.base_url = "http://localhost:8080".to_string();
    relay.allow_insecure_localhost = true;
    config.evidence.relay = Some(relay);
    config.deployment.profile = Some(crate::deployment::DeploymentProfile::Local);
    config
        .validate()
        .expect_err("local development HTTP requires a literal loopback origin");

    let mut config = valid_registry_backed_config();
    let mut relay = relay_connection();
    relay.base_url = "http://127.0.0.1:8080".to_string();
    relay.allow_insecure_localhost = true;
    config.evidence.relay = Some(relay);
    config.deployment.profile = Some(crate::deployment::DeploymentProfile::HostedLab);
    let error = config
        .validate()
        .expect_err("HTTP Relay is restricted to the local deployment profile");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidRelayConfig { ref reason }
            if reason.contains("deployment.profile = local")
    ));

    let sensitive_path = "private-route";
    let mut config = valid_registry_backed_config();
    let mut relay = relay_connection();
    relay.base_url = format!("https://relay.internal.example/{sensitive_path}");
    config.evidence.relay = Some(relay);
    let error = config
        .validate()
        .expect_err("Relay base URL must be an origin in v1");
    let rendered = error.to_string();
    assert!(rendered.contains("path exactly /"));
    assert!(!rendered.contains("relay.internal.example"));
    assert!(!rendered.contains(sensitive_path));

    let mut config = valid_registry_backed_config();
    let mut relay = relay_connection();
    relay.base_url = "https://relay.internal.example/private/..".to_string();
    config.evidence.relay = Some(relay);
    config
        .validate()
        .expect_err("a resource path must fail before URL normalization");
}

#[test]
fn self_attested_claims_are_source_free_across_dependencies() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("source-free");
    claim.evidence_mode = ClaimEvidenceMode::SelfAttested;
    config.evidence.claims.push(claim);
    config.validate().expect("source-free CEL claim validates");

    let mut source_rule = config.clone();
    source_rule.evidence.claims[0].rule = RuleConfig::ConsultationMatched {
        consultation: "implicit-source".to_string(),
    };
    expect_mode_error(&source_rule, "cannot name a Relay consultation");

    let mut plugin_rule = config.clone();
    plugin_rule.evidence.claims[0].rule = RuleConfig::Plugin {
        plugin: "unavailable".to_string(),
    };
    expect_mode_error(&plugin_rule, "supports only CEL");

    let mut config = config.clone();
    config.evidence.claims[0].required_scopes = vec!["self:read".to_string(); 2];
    expect_mode_error(&config, "duplicate");
}

#[test]
fn self_attestation_allowed_claim_closures_reject_registry_backed_modes() {
    let mut config = valid_self_attestation_config();
    config.evidence.relay = Some(relay_connection());
    make_registry_backed(&mut config.evidence.claims[0], "civil_status");
    expect_self_attestation_closure_error(&config);

    let mut config = valid_self_attestation_config();
    config.evidence.relay = Some(relay_connection());
    let mut dependency = minimal_claim("registry-dependency");
    make_registry_backed(&mut dependency, "civil_status");
    config.evidence.claims[0]
        .depends_on
        .push(dependency.id.clone());
    config.evidence.claims.push(dependency);
    expect_self_attestation_closure_error(&config);
}

#[test]
fn registry_backed_v1_rejects_all_claim_dependencies() {
    let mut config = valid_registry_backed_config();
    let dependency = minimal_claim("self-attested-dependency");
    config.evidence.claims[0]
        .depends_on
        .push(dependency.id.clone());
    config.evidence.claims.push(dependency);
    expect_mode_error(&config, "cannot declare depends_on");
}

#[test]
fn claim_dependency_graph_has_fixed_v1_node_and_edge_bounds() {
    let mut too_many_nodes = minimal_config();
    too_many_nodes.evidence.claims = (0..=MAX_CLAIM_DEPENDENCY_NODES_V1)
        .map(|index| minimal_claim(&format!("claim-{index}")))
        .collect();
    assert!(matches!(
        too_many_nodes.validate(),
        Err(EvidenceConfigError::ClaimDependencyGraphTooLarge { nodes, .. })
            if nodes == MAX_CLAIM_DEPENDENCY_NODES_V1 + 1
    ));

    let mut too_many_edges = minimal_config();
    for index in 0..24 {
        let mut claim = minimal_claim(&format!("claim-{index}"));
        claim.depends_on = (0..index)
            .map(|dependency| format!("claim-{dependency}"))
            .collect();
        too_many_edges.evidence.claims.push(claim);
    }
    assert!(matches!(
        too_many_edges.validate(),
        Err(EvidenceConfigError::ClaimDependencyGraphTooLarge { edges, .. })
            if edges > MAX_CLAIM_DEPENDENCY_EDGES_V1
    ));
}

#[test]
fn delegated_self_attestation_allows_only_its_configured_registry_proof_edge() {
    let config = valid_delegated_self_attestation_config();
    config
        .validate()
        .expect("configured delegated Relay proof edge validates");

    let mut ordinary = config.clone();
    ordinary
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "date-of-birth")
        .expect("ordinary self-attested claim")
        .depends_on = vec!["guardian-link".to_string()];
    expect_self_attestation_closure_error(&ordinary);

    let mut registry_dependent = config;
    let delegated = registry_dependent
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "dependent-date-of-birth")
        .expect("delegated claim");
    make_registry_backed(delegated, "civil_status");
    expect_self_attestation_closure_error(&registry_dependent);
}

#[test]
fn delegated_relay_proof_requires_requester_target_boolean_and_purpose_alignment() {
    let mut missing_requester = valid_delegated_self_attestation_config();
    delegated_proof_consultation_mut(&mut missing_requester)
        .inputs
        .retain(|_, input| input.is_target_derived());
    let reason = expect_self_attestation_error(&missing_requester);
    assert!(reason.contains("requester-derived and target-derived"));

    let mut missing_target = valid_delegated_self_attestation_config();
    delegated_proof_consultation_mut(&mut missing_target)
        .inputs
        .retain(|_, input| input.is_requester_derived());
    let reason = expect_self_attestation_error(&missing_target);
    assert!(reason.contains("requester-derived and target-derived"));

    let mut non_boolean = valid_delegated_self_attestation_config();
    let proof = non_boolean
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "guardian-link")
        .expect("delegated proof claim");
    proof.value.value_type = "string".to_string();
    delegated_proof_consultation_mut(&mut non_boolean).outputs = BTreeMap::from([(
        "established".to_string(),
        RelayOutputContract::String {
            nullable: true,
            max_bytes: 16,
        },
    )]);
    let reason = expect_self_attestation_error(&non_boolean);
    assert!(reason.contains("must produce a boolean result"));

    let mut wrong_purpose = valid_delegated_self_attestation_config();
    wrong_purpose
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "guardian-link")
        .expect("delegated proof claim")
        .purpose = Some("different-purpose".to_string());
    let reason = expect_self_attestation_error(&wrong_purpose);
    assert!(reason.contains("must declare the same purpose"));
}

fn delegated_proof_consultation_mut(
    config: &mut StandaloneRegistryNotaryConfig,
) -> &mut RelayConsultationConfig {
    let proof = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "guardian-link")
        .expect("delegated proof claim");
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut proof.evidence_mode else {
        panic!("delegated proof is registry backed")
    };
    consultations
        .get_mut("guardian_link")
        .expect("delegated proof consultation")
}

#[test]
fn registry_backed_cel_accepts_one_complete_typed_output_map_and_full_date_variable() {
    let mut config = valid_registry_backed_config();
    config.evidence.variables.insert(
        "as_of_date".to_string(),
        RequestVariableConfig {
            from: "request.variables.as_of_date".to_string(),
            value_type: RequestVariableType::Date,
        },
    );
    let claim = &mut config.evidence.claims[0];
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
        panic!("registry-backed mode")
    };
    let consultation = consultations
        .get_mut("person_status")
        .expect("consultation exists");
    consultation.outputs = BTreeMap::from([
        (
            "date_of_birth".to_string(),
            RelayOutputContract::Date { nullable: true },
        ),
        (
            "sequence".to_string(),
            RelayOutputContract::Integer {
                nullable: false,
                minimum: 0,
                maximum: 9_007_199_254_740_991,
            },
        ),
        (
            "status".to_string(),
            RelayOutputContract::String {
                nullable: false,
                max_bytes: 64,
            },
        ),
    ]);
    claim.rule = RuleConfig::Cel {
        expression: "person_status.matched && person_status.date_of_birth != null ? date.age_on(person_status.date_of_birth, as_of_date) >= 18 : false".to_string(),
        bindings: CelBindingsConfig::default(),
    };
    claim.value.value_type = "boolean".to_string();
    claim.value.nullable = false;
    config
        .validate()
        .expect("typed registry CEL config validates");

    let mut generic_number = config.clone();
    generic_number.evidence.claims[0].value.value_type = "number".to_string();
    expect_mode_error(&generic_number, "generic Number is not supported");

    config
        .evidence
        .variables
        .get_mut("as_of_date")
        .expect("variable exists")
        .from = "request.target.attributes.as_of_date".to_string();
    assert!(matches!(
        config.validate(),
        Err(EvidenceConfigError::InvalidRequestVariableConfig { .. })
    ));
}

#[test]
fn authored_typed_output_and_variable_yaml_shape_is_closed() {
    let evidence: EvidenceConfig = serde_norway::from_str(
        r#"
enabled: true
variables:
  as_of_date:
    from: request.variables.as_of_date
    type: date
"#,
    )
    .expect("authored request-variable union parses");
    assert_eq!(
        evidence.variables["as_of_date"].value_type,
        RequestVariableType::Date
    );

    let consultation: RelayConsultationConfig = serde_norway::from_str(
        r#"
profile:
  id: opencrvs.birth-record.exact
  contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
inputs:
  uin: request.target.identifiers.UIN
outputs:
  active: { type: boolean, nullable: false }
  date_of_birth: { type: date, nullable: true }
  sequence: { type: integer, nullable: false, minimum: 0, maximum: 9007199254740991 }
  given_name: { type: string, nullable: true, max_bytes: 128 }
"#,
    )
    .expect("authored typed consultation parses");
    assert_eq!(consultation.outputs.len(), 4);
    assert!(matches!(
        consultation.outputs.get("date_of_birth"),
        Some(RelayOutputContract::Date { nullable: true })
    ));

    assert!(serde_norway::from_str::<RelayConsultationConfig>(
        r#"
profile:
  id: opencrvs.birth-record.exact
  contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
inputs: { uin: request.target.identifiers.UIN }
outputs:
  score: { type: number, nullable: false }
"#,
    )
    .is_err());
}
