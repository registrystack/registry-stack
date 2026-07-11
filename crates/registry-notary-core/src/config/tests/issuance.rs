use super::support::*;
use super::*;
#[allow(unused_imports)]
use super::{auth::*, credentials::*, infrastructure::*, preauth::*, root::*, sources::*};

#[test]
pub(super) fn self_attestation_is_disabled_by_default() {
    let config = minimal_config();
    assert!(!config.self_attestation.enabled);
    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn oid4vci_is_disabled_by_default() {
    let config = minimal_config();
    assert!(!config.oid4vci.enabled);
    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn disabled_default_self_attestation_is_omitted_from_serialized_config() {
    let config = minimal_config();
    let serialized = serde_json::to_value(&config).expect("config serializes as JSON");

    assert!(
        serialized.get("self_attestation").is_none(),
        "disabled default self_attestation must stay compact when serialized: {serialized}",
    );
}

#[test]
pub(super) fn disabled_default_oid4vci_is_omitted_from_serialized_config() {
    let config = minimal_config();
    let serialized = serde_json::to_value(&config).expect("config serializes as JSON");

    assert!(
        serialized.get("oid4vci").is_none(),
        "disabled default oid4vci must stay compact when serialized: {serialized}",
    );
}

#[test]
pub(super) fn valid_self_attestation_config_passes_validation() {
    let config = valid_self_attestation_config();
    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn delegated_attestation_requires_bound_proof_claim_source_inputs() {
    let mut config = valid_delegated_self_attestation_config();
    let proof = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "guardian-link")
        .expect("proof claim exists");
    proof
        .source_bindings
        .get_mut("crvs")
        .expect("proof binding exists")
        .query_fields
        .clear();

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("must bind both requester and target source inputs"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn delegated_attestation_rejects_unsupported_allowed_disclosure() {
    let mut config = valid_delegated_self_attestation_config();
    config.self_attestation.delegation.allowed_relationships[0].allowed_disclosures =
        vec!["predicate".to_string()];

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("must support at least one allowed disclosure"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn valid_oid4vci_config_passes_validation() {
    let config = valid_oid4vci_config();
    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn valid_oid4vci_projection_config_passes_validation() {
    let config = valid_oid4vci_projection_config();
    config
        .validate()
        .expect("projection credential config validates");
}

#[test]
pub(super) fn oid4vci_projection_rejects_claim_id_and_claims_together() {
    let mut config = valid_oid4vci_projection_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .claim_id = Some("date-of-birth".to_string());

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("exactly one of claim_id or claims"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_projection_rejects_missing_claim_mode() {
    let mut config = valid_oid4vci_config();
    let credential = config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap();
    credential.claim_id = None;
    credential.claims.clear();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("exactly one of claim_id or claims"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_projection_rejects_duplicate_output_paths() {
    let mut config = valid_oid4vci_projection_config();
    let credential = config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap();
    credential.claims[1].output_path = vec!["birth_date".to_string()];

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("duplicate") && reason.contains("output_path"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_projection_rejects_duplicate_claim_ids() {
    let mut config = valid_oid4vci_projection_config();
    let credential = config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap();
    credential.claims[1].id = "date-of-birth".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("duplicate") && reason.contains("claims[].id"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_projection_rejects_reserved_output_paths() {
    for reserved in [
        "iss",
        "sub",
        "aud",
        "iat",
        "nbf",
        "exp",
        "vct",
        "vct#integrity",
        "id",
        "jti",
        "_sd",
        "_sd_alg",
        "cnf",
        "status",
        "issuanceDate",
        "expirationDate",
    ] {
        let mut config = valid_oid4vci_projection_config();
        config
            .oid4vci
            .credential_configurations
            .get_mut("date_of_birth_sd_jwt")
            .unwrap()
            .claims[0]
            .output_path = vec![reserved.to_string()];

        let reason = expect_oid4vci_error(&config);
        assert!(
            reason.contains("reserved") && reason.contains(reserved),
            "unexpected for {reserved}: {reason}"
        );
    }
}

#[test]
pub(super) fn oid4vci_projection_rejects_nested_output_paths_in_v1() {
    let mut config = valid_oid4vci_projection_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .claims[0]
        .output_path = vec!["birth".to_string(), "date".to_string()];

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("single segment"), "unexpected: {reason}");
}

#[test]
pub(super) fn oid4vci_projection_rejects_unknown_claim_reference() {
    let mut config = valid_oid4vci_projection_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .claims[0]
        .id = "missing-claim".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("unknown claim 'missing-claim'"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_projection_rejects_claim_outside_profile_allow_list() {
    let mut config = valid_oid4vci_projection_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .allowed_claims
        .retain(|claim_id| claim_id != "birth-place");

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("profile") && reason.contains("does not allow"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_projection_rejects_mixed_claim_purposes() {
    let mut config = valid_oid4vci_projection_config();
    config
        .self_attestation
        .allowed_purposes
        .push("other_purpose".to_string());
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "birth-place")
        .expect("projection claim exists");
    claim.purpose = Some("other_purpose".to_string());

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("share one purpose"), "unexpected: {reason}");
}

#[test]
pub(super) fn oid4vci_projection_rejects_non_value_default_disclosure() {
    let mut config = valid_oid4vci_projection_config();
    let claim = config
        .evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "birth-place")
        .expect("projection claim exists");
    claim.disclosure.default = "redacted".to_string();
    claim.disclosure.allowed = vec!["redacted".to_string(), "value".to_string()];

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("must use value as the default disclosure"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn claim_semantics_accepts_publicschema_property_mapping() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "civil_registry".to_string(),
        serde_norway::from_str(
            r#"
base_url: https://registry.example.gov
token_env: CIVIL_REGISTRY_TOKEN
"#,
        )
        .expect("source connection parses"),
    );
    config.evidence.claims.push(
        serde_norway::from_str(
            r#"
id: date-of-birth
title: Date of birth
version: "2026-06"
subject_type: person
evidence_mode:
  type: transitional_direct
value:
  type: date
semantics:
  concept: https://publicschema.org/Person
  property: " https://publicschema.org/date_of_birth "
  value_mapping: publicschema
source_bindings:
  civil:
    connector: registry_data_api
    connection: civil_registry
    dataset: civil_registry
    entity: person
    lookup:
      input: target.identifiers.national_id
      field: national_id
      cardinality: one
    fields:
      birth_date:
        field: birth_date
        type: date
        required: true
        semantic_term: " https://publicschema.org/date_of_birth "
rule:
  type: extract
  source: civil
  field: birth_date
"#,
        )
        .expect("claim parses"),
    );

    config
        .validate()
        .expect("matching PublicSchema semantics validate");
}

#[test]
pub(super) fn claim_semantics_rejects_conflicting_extract_field_mapping() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "civil_registry".to_string(),
        serde_norway::from_str(
            r#"
base_url: https://registry.example.gov
token_env: CIVIL_REGISTRY_TOKEN
"#,
        )
        .expect("source connection parses"),
    );
    config.evidence.claims.push(
        serde_norway::from_str(
            r#"
id: date-of-birth
title: Date of birth
version: "2026-06"
subject_type: person
evidence_mode:
  type: transitional_direct
semantics:
  property: https://publicschema.org/date_of_birth
source_bindings:
  civil:
    connector: registry_data_api
    connection: civil_registry
    dataset: civil_registry
    entity: person
    lookup:
      input: target.identifiers.national_id
      field: national_id
      cardinality: one
    fields:
      birth_date:
        field: birth_date
        type: date
        required: true
        semantic_term: https://publicschema.org/date_of_death
rule:
  type: extract
  source: civil
  field: birth_date
"#,
        )
        .expect("claim parses"),
    );

    let error = config
        .validate()
        .expect_err("conflicting semantic terms must fail validation");
    assert!(
        matches!(error, EvidenceConfigError::InvalidClaimSemantics { ref reason, .. } if reason.contains("conflicts with source field")),
        "unexpected error: {error:?}"
    );
}

#[test]
pub(super) fn oid4vci_accepts_vct_under_path_prefixed_credential_issuer() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.credential_issuer = "http://127.0.0.1:4325/notary".to_string();
    config.oid4vci.credential_endpoint =
        "http://127.0.0.1:4325/notary/oid4vci/credential".to_string();
    config.oid4vci.offer_endpoint =
        "http://127.0.0.1:4325/notary/oid4vci/credential-offer".to_string();
    config.oid4vci.nonce_endpoint = Some("http://127.0.0.1:4325/notary/oid4vci/nonce".to_string());
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .vct = "http://127.0.0.1:4325/notary/credentials/civil-status".to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .vct = "http://127.0.0.1:4325/notary/credentials/civil-status".to_string();

    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn oid4vci_deserializes_absent_block_with_default() {
    let config = valid_self_attestation_config();
    assert_eq!(config.oid4vci, Oid4vciConfig::default());
}

#[test]
pub(super) fn oid4vci_requires_enabled_self_attestation() {
    let mut config = valid_oid4vci_config();
    config.self_attestation.enabled = false;

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("self_attestation.enabled"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_rejects_missing_accepted_audiences() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.accepted_token_audiences.clear();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("accepted_token_audiences"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_rejects_unknown_claim_reference() {
    let mut config = valid_oid4vci_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .claim_id = Some("missing-claim".to_string());

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("unknown claim 'missing-claim'"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_rejects_unknown_credential_profile_reference() {
    let mut config = valid_oid4vci_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .credential_profile = "missing-profile".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("unknown credential profile 'missing-profile'"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_rejects_non_loopback_http_urls() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.credential_issuer = "http://issuer.example".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("https") && reason.contains("loopback"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_rejects_endpoint_without_path() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.credential_endpoint = "http://127.0.0.1:4325".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("endpoint path"), "unexpected: {reason}");
}

#[test]
pub(super) fn oid4vci_rejects_vct_outside_credential_issuer() {
    let mut config = valid_oid4vci_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .vct = "https://vct.example/credentials/civil-status".to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .vct = "https://vct.example/credentials/civil-status".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("credential_configurations.vct")
            && reason.contains("oid4vci.credential_issuer"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_rejects_vct_outside_credentials_path() {
    let mut config = valid_oid4vci_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .vct = "http://127.0.0.1:4325/not-credentials/civil-status".to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .vct = "http://127.0.0.1:4325/not-credentials/civil-status".to_string();

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("vct path") && reason.contains("/credentials/"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_rejects_duplicate_credential_configuration_vct() {
    let mut config = valid_oid4vci_config();
    let duplicate = config
        .oid4vci
        .credential_configurations
        .get("date_of_birth_sd_jwt")
        .unwrap()
        .clone();
    config
        .oid4vci
        .credential_configurations
        .insert("duplicate_sd_jwt".to_string(), duplicate);

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("vct") && reason.contains("unique"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_rejects_missing_nonce_endpoint_when_nonce_enabled() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.nonce_endpoint = None;

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("nonce_endpoint"), "unexpected: {reason}");
}

#[test]
pub(super) fn oid4vci_rejects_bad_nonce_and_proof_timing_bounds() {
    let mut config = valid_oid4vci_config();
    config.oid4vci.nonce.ttl_seconds = 0;

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("nonce.ttl_seconds"), "unexpected: {reason}");

    config.oid4vci.nonce.ttl_seconds = 300;
    config.oid4vci.proof.max_age_seconds = 601;

    let reason = expect_oid4vci_error(&config);
    assert!(
        reason.contains("proof.max_age_seconds"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn oid4vci_rejects_bad_algorithm_lists() {
    let mut config = valid_oid4vci_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .proof_signing_alg_values_supported
        .push("ES256".to_string());

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("ES256"), "unexpected: {reason}");
}

#[test]
pub(super) fn oid4vci_rejects_bad_binding_methods() {
    let mut config = valid_oid4vci_config();
    config
        .oid4vci
        .credential_configurations
        .get_mut("date_of_birth_sd_jwt")
        .unwrap()
        .cryptographic_binding_methods_supported
        .push("did:key".to_string());

    let reason = expect_oid4vci_error(&config);
    assert!(reason.contains("did:key"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_requires_oidc_auth_mode() {
    let mut config = valid_self_attestation_config();
    config.auth.mode = EvidenceAuthMode::ApiKey;
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "api".to_string(),
        fingerprint: CredentialFingerprintRef {
            provider: registry_platform_authcommon::CredentialFingerprintProvider::Env,
            name: Some("API_HASH".to_string()),
            path: None,
        },
        scopes: Vec::new(),
        authorization_details: None,
    });

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("auth.mode = oidc"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_rejects_unsafe_subject_claim_names() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.subject_binding.token_claim = "national id".to_string();

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("token_claim"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_rejects_sub_without_explicit_civil_id_opt_in() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.subject_binding.token_claim = "sub".to_string();

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("allow_sub_as_civil_id"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_allows_sub_with_explicit_civil_id_opt_in() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.subject_binding.token_claim = "sub".to_string();
    config
        .self_attestation
        .subject_binding
        .allow_sub_as_civil_id = true;

    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn self_attestation_subject_request_field_only_accepts_subject_id() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: oidc
  oidc:
    issuer: https://id.example.gov
    jwks_url: https://id.example.gov/keys
    audiences:
      - registry-notary-citizen
self_attestation:
  enabled: true
  subject_binding:
    token_claim: https://id.example.gov/claims/national_id
    request_field: SubjectHeader
    id_type: national_id
"#,
    )
    .expect_err("unsupported request_field variant must fail deserialization");
    let msg = err.to_string();
    assert!(
        msg.contains("SubjectHeader") || msg.contains("unknown variant"),
        "unexpected error: {msg}"
    );
}

#[test]
pub(super) fn shared_canonical_oidc_fixture_parses() {
    let config = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: oidc
  oidc:
    issuer: https://id.example.gov
    audiences:
      - registry-notary
    jwks_url: https://id.example.gov/oauth/v2/keys
    allowed_algorithms:
      - EdDSA
    allowed_token_types:
      - JWT
    leeway: 30s
"#,
    )
    .expect("shared canonical OIDC fixture parses");
    let oidc = config.auth.oidc.expect("oidc config");

    assert_eq!(oidc.issuer, "https://id.example.gov");
    assert_eq!(oidc.audiences, vec!["registry-notary"]);
    assert_eq!(oidc.jwks_url, "https://id.example.gov/oauth/v2/keys");
    assert_eq!(oidc.allowed_algorithms, vec!["EdDSA"]);
    assert_eq!(oidc.allowed_token_types, vec!["JWT"]);
    assert_eq!(oidc.leeway, Duration::from_secs(30));
}

#[test]
pub(super) fn self_attestation_rejects_non_exact_normalization() {
    let err = serde_norway::from_str::<StandaloneRegistryNotaryConfig>(
        r#"
evidence:
  enabled: true
auth:
  mode: oidc
  oidc:
    issuer: https://id.example.gov
    jwks_url: https://id.example.gov/keys
    audiences:
      - registry-notary-citizen
self_attestation:
  enabled: true
  subject_binding:
    token_claim: https://id.example.gov/claims/national_id
    request_field: SubjectId
    id_type: national_id
    normalize: lowercase
"#,
    )
    .expect_err("unsupported normalize variant must fail deserialization");
    let msg = err.to_string();
    assert!(
        msg.contains("lowercase") || msg.contains("unknown variant"),
        "unexpected error: {msg}"
    );
}

#[test]
pub(super) fn self_attestation_requires_nonempty_allow_lists() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.allowed_claims.clear();

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("allowed_claims must not be empty"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_rejects_unused_allow_list_entries() {
    let mut config = valid_self_attestation_config();
    config
        .self_attestation
        .allowed_formats
        .push("application/unsupported".to_string());

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("allowed_formats entry"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_rejects_batch_evaluate_operation() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.allowed_operations.batch_evaluate = true;

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("batch_evaluate"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_rejects_wildcard_wallet_origins() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.allowed_wallet_origins = vec!["*".to_string()];

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("wildcards"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_allows_empty_wallet_origins_for_non_browser_flows() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.allowed_wallet_origins.clear();

    config
        .validate()
        .expect("wallet origins are optional for CLI and server-side flows");
}

#[test]
pub(super) fn self_attestation_rejects_zero_rate_limits() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.rate_limits.per_principal_per_minute = 0;

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("rate_limits"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_requires_allowed_client_or_audience() {
    let mut config = valid_self_attestation_config();
    config
        .self_attestation
        .citizen_clients
        .allowed_client_ids
        .clear();
    config
        .self_attestation
        .citizen_clients
        .allowed_audiences
        .clear();

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("citizen_clients"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_requires_scopes_to_be_mapped() {
    let mut config = valid_self_attestation_config();
    config.auth.oidc.as_mut().unwrap().scope_map.clear();

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("scope_map"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_required_scope_policy_requires_scopes() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.required_scopes.clear();

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("scope_policy requires required_scopes"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_optional_scope_policy_still_requires_scope_mapping() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.scope_policy = SelfAttestationScopePolicy::Optional;
    config.auth.oidc.as_mut().unwrap().scope_map.clear();

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("scope_map"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_optional_scope_policy_passes_with_required_scopes() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.scope_policy = SelfAttestationScopePolicy::Optional;

    config
        .validate()
        .expect("optional scope policy uses configured self-attestation scopes");
}

#[test]
pub(super) fn self_attestation_disabled_scope_policy_rejects_required_scopes() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.scope_policy = SelfAttestationScopePolicy::Disabled;

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("scope_policy = disabled"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_rejects_citizen_scope_map_granting_source_scope() {
    let mut config = valid_self_attestation_config();
    config.auth.oidc.as_mut().unwrap().scope_map.insert(
        "citizen_self_attestation".to_string(),
        vec![
            "self_attestation".to_string(),
            "civil_registry:evidence_verification".to_string(),
        ],
    );

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("must not grant source scope"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_rejects_leeway_above_token_policy() {
    let mut config = valid_self_attestation_config();
    config.auth.oidc.as_mut().unwrap().leeway = Duration::from_secs(61);

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("leeway"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_rejects_unknown_claim_references() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.allowed_claims = vec!["missing-claim".to_string()];

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("unknown claim 'missing-claim'"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_rejects_unallowed_claim_purpose() {
    let mut config = valid_self_attestation_config();
    config.evidence.claims[0].purpose = Some("machine_verification".to_string());

    let reason = expect_self_attestation_error(&config);
    assert!(reason.contains("unallowed purpose"), "unexpected: {reason}");
}

#[test]
pub(super) fn self_attestation_rejects_claim_without_purpose() {
    let mut config = valid_self_attestation_config();
    config.evidence.claims[0].purpose = None;

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("must declare purpose"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_rejects_unknown_profile_references() {
    let mut config = valid_self_attestation_config();
    config.self_attestation.credential_profiles = vec!["missing-profile".to_string()];

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("unknown profile 'missing-profile'"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_rejects_citizen_profile_validity_above_ceiling() {
    let mut config = valid_self_attestation_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .validity_seconds = 601;

    let error = config
        .validate()
        .expect_err("validity above general ceiling is rejected");
    assert!(matches!(
        error,
        EvidenceConfigError::InvalidCredentialProfileValidity {
            profile,
            validity_seconds: 601,
            max_validity_seconds: 600,
        } if profile == "civil_status_sd_jwt"
    ));
}

#[test]
pub(super) fn self_attestation_accepts_citizen_profile_validity_at_configured_ceiling() {
    const AGENCY_CREDENTIAL_VALIDITY_SECONDS: u64 = 31_536_000;
    let mut config = valid_self_attestation_config();
    config.evidence.max_credential_validity_seconds = AGENCY_CREDENTIAL_VALIDITY_SECONDS;
    config
        .self_attestation
        .token_policy
        .max_credential_validity_seconds = AGENCY_CREDENTIAL_VALIDITY_SECONDS;
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .validity_seconds = AGENCY_CREDENTIAL_VALIDITY_SECONDS as i64;

    config
        .validate()
        .expect("wallet-held credential validity may reach the configured ceiling");
}

#[test]
pub(super) fn self_attestation_profile_without_validity_uses_default_under_ceiling() {
    let mut config = valid_self_attestation_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: did:web:issuer.example
signing_key: issuer-key
vct: https://issuer.example/credentials/civil-status
holder_binding:
  mode: did
  proof_of_possession: required
  allowed_did_methods:
    - did:jwk
allowed_claims:
  - date-of-birth
disclosure:
  allowed:
    - value
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("civil_status_sd_jwt".to_string(), profile);

    config
        .validate()
        .expect("omitted credential validity defaults under self-attestation ceiling");
    assert_eq!(
        config
            .evidence
            .credential_profiles
            .get("civil_status_sd_jwt")
            .unwrap()
            .validity_seconds,
        600
    );
}

#[test]
pub(super) fn self_attestation_rejects_profile_without_did_holder_binding() {
    let mut config = valid_self_attestation_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .holder_binding
        .mode = "none".to_string();

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("holder_binding.mode must be did"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_rejects_profile_without_required_holder_proof() {
    let mut config = valid_self_attestation_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .holder_binding
        .proof_of_possession = None;

    let reason = expect_self_attestation_error(&config);
    assert!(
        reason.contains("holder_binding.proof_of_possession must be required"),
        "unexpected: {reason}"
    );
}

#[test]
pub(super) fn self_attestation_keeps_did_jwk_proof_of_possession_validation() {
    let mut config = valid_self_attestation_config();
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .unwrap()
        .holder_binding
        .allowed_did_methods
        .push("did:key".to_string());

    let err = config
        .validate()
        .expect_err("did:key must still fail proof-of-possession validation");
    assert!(matches!(
        err,
        EvidenceConfigError::UnsupportedCredentialProfileDidMethods { .. }
    ));
}

pub(super) fn second_signing_key() -> SigningKeyConfig {
    serde_norway::from_str(
        r#"
provider: local_jwk_env
private_jwk_env: ACCESS_TOKEN_KEY
alg: EdDSA
kid: did:web:issuer.example#access-token-key
status: active
"#,
    )
    .expect("access-token signing key is valid YAML")
}

pub(super) fn publish_only_access_token_verification_key(kid: &str) -> SigningKeyConfig {
    let mut key = second_signing_key();
    key.kid = kid.to_string();
    key.status = SigningKeyStatus::PublishOnly;
    key.private_jwk_env = String::new();
    key.public_jwk_env = "ACCESS_TOKEN_PUBLIC_KEY".to_string();
    key
}

pub(super) fn test_public_jwk(kid: &str, x: &str) -> PublicJwk {
    PublicJwk::parse(
        &serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "alg": "EdDSA",
            "kid": kid,
        })
        .to_string(),
    )
    .expect("test public JWK parses")
}

/// A pre-auth-enabled oid4vci config with a dedicated access-token signing
/// key, distinct from the credential-signing key.
pub(super) fn valid_pre_auth_config() -> StandaloneRegistryNotaryConfig {
    let mut config = valid_oid4vci_config();
    config
        .self_attestation
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 5;
    config
        .evidence
        .signing_keys
        .insert("access-token-key".to_string(), second_signing_key());
    config.oid4vci.pre_authorized_code = serde_norway::from_str(
        r#"
enabled: true
tx_code:
  required: true
  input_mode: numeric
  length: 6
esignet:
  client_id: registry-lab-live-client
  client_signing_key_id: issuer-key
  redirect_uri: http://127.0.0.1:4325/oid4vci/offer/callback
  authorize_url: https://id.example.gov/authorize
  token_url: https://id.example.gov/oauth/v2/token
  issuer: https://id.example.gov
  jwks_uri: https://id.example.gov/oauth/.well-known/jwks.json
  scopes:
    - openid
pre_authorized_code_ttl_seconds: 300
"#,
    )
    .expect("pre-auth config is valid YAML");
    config.auth.access_token_signing = serde_norway::from_str(
        r#"
enabled: true
issuer: http://127.0.0.1:4325
audiences:
  - http://127.0.0.1:4325
allowed_algorithms:
  - EdDSA
token_typ: registry-notary-access+jwt
signing_key_id: access-token-key
access_token_ttl_seconds: 300
"#,
    )
    .expect("access-token signing config is valid YAML");
    config
}

pub(super) fn expect_access_token_signing_error(config: &StandaloneRegistryNotaryConfig) -> String {
    match config
        .validate()
        .expect_err("access-token signing config must fail validation")
    {
        EvidenceConfigError::InvalidAccessTokenSigningConfig { reason } => reason,
        other => panic!("unexpected error variant: {other}"),
    }
}
