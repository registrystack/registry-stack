use super::root::{
    minimal_claim, valid_delegated_self_attestation_config, valid_self_attestation_config,
};
use super::support::minimal_config;
use super::*;

const CONTRACT_HASH: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn relay_connection() -> RelayConnectionConfig {
    serde_norway::from_str(
        r#"
base_url: https://relay.internal.example
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
                    version: "1".to_string(),
                    contract_hash: CONTRACT_HASH.to_string(),
                },
                inputs: std::collections::BTreeMap::from([(
                    "subject_id".to_string(),
                    RelayConsultationInput::TargetId,
                )]),
            },
        )]),
    }
}

fn make_registry_backed(claim: &mut ClaimDefinition, consultation_name: &str) {
    claim.evidence_mode = registry_mode(consultation_name);
    claim.source_bindings.clear();
    claim.purpose = Some("benefit-verification".to_string());
    claim.required_scopes = vec!["registry:consult:person-status".to_string()];
    claim.value.value_type = "string".to_string();
    claim.rule = RuleConfig::Extract {
        source: consultation_name.to_string(),
        field: "registration_status".to_string(),
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

    serde_norway::from_str::<ClaimDefinition>(
        r#"
id: mixed-transition
title: Mixed transition
version: "1"
subject_type: person
evidence_mode:
  type: transitional_direct
  consultations: {}
rule:
  type: cel
  expression: "true"
"#,
    )
    .expect_err("transitional direct cannot configure consultations");
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
        version: "1"
        contract_hash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      inputs:
        subject_id: target.id
      route: /private/person
rule:
  type: exists
  source: person_status
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
        version: "1"
        contract_hash: {CONTRACT_HASH}
      inputs:
        subject_id: {sensitive_target}
rule:
  type: exists
  source: person_status
"#
    ))
    .expect_err("only the symbolic target.id mapping is accepted");
    assert!(!error.to_string().contains(sensitive_target));
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
fn initial_relay_activation_shape_is_one_shared_product_journey() {
    let mut config = valid_registry_backed_config();
    let mut exists = config.evidence.claims[0].clone();
    exists.id = "person-status-present".to_string();
    exists.title = "Person status known".to_string();
    exists.rule = RuleConfig::Exists {
        source: "person_status".to_string(),
    };
    exists.value.value_type = "boolean".to_string();
    config.evidence.claims.push(exists);
    config
        .validate()
        .expect("exists and extract claims may share one pinned consultation");

    let mut exists_only = config.clone();
    exists_only.evidence.claims.remove(0);
    exists_only
        .validate()
        .expect("an exists-only journey selects the explicit presence-only Relay contract");

    let mut different_profile = config.clone();
    let ClaimEvidenceMode::RegistryBacked { consultations } =
        &mut different_profile.evidence.claims[1].evidence_mode
    else {
        panic!("registry-backed mode")
    };
    consultations
        .get_mut("person_status")
        .expect("consultation")
        .profile
        .version = "2".to_string();
    expect_mode_error(
        &different_profile,
        "one shared profile, purpose, and input name",
    );

    let mut different_output = config;
    different_output.evidence.claims[1].rule = RuleConfig::Extract {
        source: "person_status".to_string(),
        field: "other_status".to_string(),
    };
    different_output.evidence.claims[1].value.value_type = "string".to_string();
    expect_mode_error(&different_output, "one shared string output");
}

#[test]
fn registry_backed_claim_rejects_missing_or_mixed_sources() {
    let mut config = valid_registry_backed_config();
    config.evidence.relay = None;
    expect_mode_error(&config, "requires evidence.relay");

    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].source_bindings.insert(
        "person_status".to_string(),
        serde_norway::from_str(
            r#"
connector: registry_data_api
connection: old-source
dataset: people
entity: person
lookup:
  input: target.id
  field: id
"#,
        )
        .expect("legacy source binding parses"),
    );
    expect_mode_error(&config, "cannot declare source_bindings");
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
    expect_mode_error(&config, "cannot enable batch_evaluate");

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
    config.evidence.claims[0].rule = RuleConfig::Exists {
        source: "other_status".to_string(),
    };
    expect_mode_error(&config, "rule.source must match");

    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].rule = RuleConfig::Cel {
        expression: "true".to_string(),
        bindings: CelBindingsConfig::default(),
    };
    expect_mode_error(&config, "only exists and extract");
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
        .profile
        .version = "01".to_string();
    expect_mode_error(&config, "profile.version");

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
    expect_mode_error(&config, "exactly one target.id mapping");

    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].rule = RuleConfig::Exists {
        source: "person_status".to_string(),
    };
    expect_mode_error(&config, "exists claim value.type must be boolean");

    let mut config = valid_registry_backed_config();
    config.evidence.claims[0].rule = RuleConfig::Extract {
        source: "person_status".to_string(),
        field: "nested.status".to_string(),
    };
    config.evidence.claims[0].value.value_type = "string".to_string();
    expect_mode_error(&config, "one top-level Relay output name");

    for unsupported in ["boolean", "integer", "number", "object"] {
        let mut config = valid_registry_backed_config();
        config.evidence.claims[0].rule = RuleConfig::Extract {
            source: "person_status".to_string(),
            field: "registration_status".to_string(),
        };
        config.evidence.claims[0].value.value_type = unsupported.to_string();
        expect_mode_error(&config, "must be string in v1");
    }
}

#[test]
fn relay_connection_is_single_closed_bounded_and_redacted() {
    let relay: RelayConnectionConfig = serde_norway::from_str(
        r#"
base_url: https://relay.internal.example
token_file: /run/secrets/private-relay.jwt
allowed_private_cidrs: [10.42.0.0/16, fd42::/64]
"#,
    )
    .expect("Relay connection parses");
    relay.validate().expect("Relay connection validates");
    assert_eq!(relay.allowed_private_cidrs.len(), 2);
    let debug = format!("{relay:?}");
    assert!(!debug.contains("relay.internal.example"));
    assert!(!debug.contains("private-relay.jwt"));
    assert!(!debug.contains("10.42.0.0/16"));

    serde_norway::from_str::<RelayConnectionConfig>(
        r#"
base_url: https://relay.internal.example
token_file: /run/secrets/relay.jwt
retry_on_5xx: true
"#,
    )
    .expect_err("retry controls are not part of the closed Relay connection");
}

#[test]
fn relay_token_file_and_private_cidrs_are_exact_and_bounded() {
    for token_file in [
        PathBuf::from("relative/relay.jwt"),
        PathBuf::from("/run/secrets/../relay.jwt"),
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
token_env: REMOVED_RELAY_TOKEN
"#,
    )
    .expect_err("the removed static environment-token mode is rejected");

    serde_norway::from_str::<RelayConnectionConfig>(
        r#"
base_url: https://relay.internal.example
token_file: /run/secrets/relay.jwt
token_issuer: REMOVED_DUPLICATE_IDENTITY
"#,
    )
    .expect_err("duplicated local workload-token semantics are rejected");
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
    config.server.request_timeout = Duration::from_secs(19) + Duration::from_millis(999);
    let error = config
        .validate()
        .expect_err("the request timeout must not expire before the Relay service hop");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidRelayConfig { ref reason }
            if reason.contains("at least 20 seconds")
    ));

    config.server.request_timeout = Duration::from_secs(20);
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
    assert!(config.gate_input().source_insecure_url);

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
    source_rule.evidence.claims[0].rule = RuleConfig::Exists {
        source: "implicit-source".to_string(),
    };
    expect_mode_error(&source_rule, "cannot name an evidence source");

    let mut plugin_rule = config.clone();
    plugin_rule.evidence.claims[0].rule = RuleConfig::Plugin {
        plugin: "unavailable".to_string(),
    };
    expect_mode_error(&plugin_rule, "supports only CEL");

    let mut source_binding = config.clone();
    source_binding.evidence.claims[0].source_bindings.insert(
        "implicit-source".to_string(),
        serde_norway::from_str(
            r#"
connector: registry_data_api
dataset: people
entity: person
lookup:
  input: target.id
  field: id
"#,
        )
        .expect("legacy source binding parses"),
    );
    expect_mode_error(&source_binding, "cannot declare source_bindings");

    let mut config = config.clone();
    config.evidence.claims[0].required_scopes = vec!["self:read".to_string(); 2];
    expect_mode_error(&config, "duplicate");

    let mut config = minimal_config();
    let dependency = minimal_claim("legacy-source");
    let mut claim = minimal_claim("source-free");
    claim.evidence_mode = ClaimEvidenceMode::SelfAttested;
    claim.depends_on.push(dependency.id.clone());
    config.evidence.claims = vec![dependency, claim];
    expect_mode_error(&config, "dependency closure");
}

#[test]
fn self_attestation_allowed_claim_closures_reject_registry_backed_modes() {
    let mut config = valid_self_attestation_config();
    config.evidence.relay = Some(relay_connection());
    make_registry_backed(&mut config.evidence.claims[0], "civil_status");
    expect_self_attestation_closure_error(&config);

    let mut config = valid_self_attestation_config();
    config.evidence.claims[0].evidence_mode = ClaimEvidenceMode::TransitionalDirect;
    config
        .validate()
        .expect("transitional direct preserves the governed legacy self-service path");

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
    let dependency = minimal_claim("legacy-dependency");
    config.evidence.claims[0]
        .depends_on
        .push(dependency.id.clone());
    config.evidence.claims.push(dependency);
    expect_mode_error(&config, "cannot declare depends_on");

    let mut config = valid_registry_backed_config();
    let mut dependency = minimal_claim("source-free-dependency");
    dependency.evidence_mode = ClaimEvidenceMode::SelfAttested;
    config.evidence.claims[0]
        .depends_on
        .push(dependency.id.clone());
    config.evidence.claims.push(dependency);
    expect_mode_error(&config, "cannot declare depends_on");

    let mut config = valid_registry_backed_config();
    let registry_id = config.evidence.claims[0].id.clone();
    let mut transitional = minimal_claim("legacy-derived-claim");
    transitional.depends_on.push(registry_id);
    config.evidence.claims.push(transitional);
    expect_mode_error(
        &config,
        "transitional_direct dependency closure cannot contain registry_backed",
    );
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
fn delegated_self_attestation_claim_closures_require_self_attested_modes() {
    let mut config = valid_delegated_self_attestation_config();
    config.evidence.relay = Some(relay_connection());
    let proof = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "guardian-link")
        .expect("proof claim");
    make_registry_backed(proof, "guardian_link");
    expect_self_attestation_closure_error(&config);

    let mut config = valid_delegated_self_attestation_config();
    config.evidence.relay = Some(relay_connection());
    let delegated = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "dependent-date-of-birth")
        .expect("delegated claim");
    make_registry_backed(delegated, "civil_status");
    expect_self_attestation_closure_error(&config);
}

#[test]
fn transitional_direct_preserves_rule_source_validation() {
    let mut config = minimal_config();
    let mut claim = minimal_claim("legacy-claim");
    claim.rule = RuleConfig::Exists {
        source: "missing-direct-binding".to_string(),
    };
    config.evidence.claims.push(claim);
    let error = config
        .validate()
        .expect_err("legacy direct rule must still name its source binding");
    assert!(matches!(
        error,
        EvidenceConfigError::UnknownRuleSourceBinding { .. }
    ));
}
