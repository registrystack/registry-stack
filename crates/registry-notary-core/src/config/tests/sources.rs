use super::support::*;
use super::*;
#[allow(unused_imports)]
use super::{auth::*, credentials::*, infrastructure::*, issuance::*, preauth::*, root::*};

#[test]
pub(super) fn source_connection_max_in_flight_zero_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "UPSTREAM_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 0,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let err = config
        .validate()
        .expect_err("max_in_flight=0 must fail validation");
    assert!(matches!(err, EvidenceConfigError::InvalidConcurrency));
}

#[test]
pub(super) fn source_connection_max_in_flight_defaults_to_eight() {
    // The YAML default for `max_in_flight` must be 8; operators do not
    // need to set it explicitly to get the documented politeness cap.
    let yaml = r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
"#;
    let connection: SourceConnectionConfig =
        serde_norway::from_str(yaml).expect("connection YAML parses");
    assert!(!connection.allow_insecure_localhost);
    assert!(!connection.allow_insecure_private_network);
    assert_eq!(connection.max_in_flight, 8);
}

#[test]
pub(super) fn source_connection_private_network_escape_hatch_deserializes() {
    let yaml = r#"
base_url: http://registry-relay:8080
allow_insecure_private_network: true
token_env: SRC_TOKEN
"#;
    let connection: SourceConnectionConfig =
        serde_norway::from_str(yaml).expect("connection YAML parses");
    assert!(connection.allow_insecure_private_network);
}

#[test]
pub(super) fn source_connection_oauth_auth_deserializes_without_static_token() {
    let yaml = r#"
base_url: https://registry.example
source_auth:
  type: oauth2_client_credentials
  token_url: https://registry.example/oauth/token
  client_id_env: SOURCE_CLIENT_ID
  client_secret_env: SOURCE_CLIENT_SECRET
  request_format: json
  scope: registry.read
  refresh_skew_seconds: 30
"#;
    let connection: SourceConnectionConfig =
        serde_norway::from_str(yaml).expect("connection YAML parses");
    assert!(connection.token_env.is_empty());
    let Some(SourceAuthConfig::Oauth2ClientCredentials(auth)) = connection.source_auth else {
        panic!("oauth source auth should deserialize");
    };
    assert_eq!(auth.request_format, "json");
    assert_eq!(auth.scope, "registry.read");
    assert_eq!(auth.refresh_skew_seconds, 30);
}

#[test]
pub(super) fn source_connection_rejects_static_token_and_source_auth_together() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: Some(SourceAuthConfig::Oauth2ClientCredentials(
                Oauth2ClientCredentialsSourceAuthConfig {
                    token_url: "https://upstream.example/oauth/token".to_string(),
                    client_id_env: "SRC_CLIENT_ID".to_string(),
                    client_secret_env: "SRC_CLIENT_SECRET".to_string(),
                    request_format: "json".to_string(),
                    scope: String::new(),
                    refresh_skew_seconds: 60,
                },
            )),
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let err = config
        .validate()
        .expect_err("token_env and source_auth must conflict");
    assert!(matches!(
        err,
        EvidenceConfigError::InvalidSourceAuthConfig { .. }
    ));
}

#[test]
pub(super) fn source_connection_rejects_unknown_oauth_request_format() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "src".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: String::new(),
            source_auth: Some(SourceAuthConfig::Oauth2ClientCredentials(
                Oauth2ClientCredentialsSourceAuthConfig {
                    token_url: "https://upstream.example/oauth/token".to_string(),
                    client_id_env: "SRC_CLIENT_ID".to_string(),
                    client_secret_env: "SRC_CLIENT_SECRET".to_string(),
                    request_format: "xml".to_string(),
                    scope: String::new(),
                    refresh_skew_seconds: 60,
                },
            )),
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let err = config
        .validate()
        .expect_err("unsupported oauth request_format must fail validation");
    match err {
        EvidenceConfigError::InvalidSourceAuthConfig { reason, .. } => {
            assert!(reason.contains("json or form"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

// -----------------------------------------------------------------------
// Stage 3: bulk_mode validation
// -----------------------------------------------------------------------

pub(super) fn rda_binding(connection: &str, cardinality: &str) -> SourceBindingConfig {
    SourceBindingConfig {
        connector: SourceConnectorKind::RegistryDataApi,
        connection: Some(connection.to_string()),
        required_scope: None,
        dataset: "farmer_registry".to_string(),
        entity: "farmer".to_string(),
        lookup: SourceLookupConfig {
            input: "target.id".to_string(),
            field: "id".to_string(),
            op: "eq".to_string(),
            cardinality: cardinality.to_string(),
        },
        query_fields: Vec::new(),
        fields: BTreeMap::new(),
        matching: SourceMatchingConfig::default(),
    }
}

pub(super) fn dci_binding(connection: &str) -> SourceBindingConfig {
    SourceBindingConfig {
        connector: SourceConnectorKind::Dci,
        connection: Some(connection.to_string()),
        required_scope: None,
        dataset: "farmer_registry".to_string(),
        entity: "farmer".to_string(),
        lookup: SourceLookupConfig {
            input: "target.id".to_string(),
            field: "id_type".to_string(),
            op: "eq".to_string(),
            cardinality: "one".to_string(),
        },
        query_fields: Vec::new(),
        fields: BTreeMap::new(),
        matching: SourceMatchingConfig::default(),
    }
}

pub(super) fn source_adapter_sidecar_binding(connection: &str) -> SourceBindingConfig {
    SourceBindingConfig {
        connector: SourceConnectorKind::SourceAdapterSidecar,
        connection: Some(connection.to_string()),
        required_scope: None,
        dataset: "civil_registry".to_string(),
        entity: "civil_person".to_string(),
        lookup: SourceLookupConfig {
            input: "target.id".to_string(),
            field: "national_id".to_string(),
            op: "eq".to_string(),
            cardinality: "one".to_string(),
        },
        query_fields: Vec::new(),
        fields: BTreeMap::new(),
        matching: SourceMatchingConfig::default(),
    }
}

pub(super) fn add_query_fields(binding: &mut SourceBindingConfig) {
    binding.query_fields = vec![
        SourceQueryFieldConfig {
            input: "target.attributes.given_name".to_string(),
            field: "given_name".to_string(),
            op: "eq".to_string(),
        },
        SourceQueryFieldConfig {
            input: "target.attributes.family_name".to_string(),
            field: "surname".to_string(),
            op: "eq".to_string(),
        },
    ];
}

#[test]
pub(super) fn dependent_source_lookup_rejects_unknown_binding_reference() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("birth-event");
    let mut binding = rda_binding("farmer_registry", "one");
    binding.lookup.input = "sources.missing.birth_event_id".to_string();
    claim
        .source_bindings
        .insert("birth_event".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("unknown dependent source binding must fail validation");
    match err {
        EvidenceConfigError::UnknownSourceLookupBinding {
            claim,
            binding,
            input,
            unknown,
        } => {
            assert_eq!(claim, "birth-event");
            assert_eq!(binding, "birth_event");
            assert_eq!(input, "sources.missing.birth_event_id");
            assert_eq!(unknown, "missing");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn dependent_source_query_field_rejects_unknown_binding_reference() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("birth-event");
    let mut binding = rda_binding("farmer_registry", "one");
    binding.query_fields = vec![SourceQueryFieldConfig {
        input: "source.missing.birth_event_id".to_string(),
        field: "birth_event_id".to_string(),
        op: "eq".to_string(),
    }];
    claim
        .source_bindings
        .insert("birth_event".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("unknown dependent query field binding must fail validation");
    match err {
        EvidenceConfigError::UnknownSourceLookupBinding {
            claim,
            binding,
            input,
            unknown,
        } => {
            assert_eq!(claim, "birth-event");
            assert_eq!(binding, "birth_event");
            assert_eq!(input, "source.missing.birth_event_id");
            assert_eq!(unknown, "missing");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn dependent_source_lookup_rejects_binding_cycle() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("birth-event");
    let mut first = rda_binding("farmer_registry", "one");
    first.lookup.input = "sources.second.birth_event_id".to_string();
    let mut second = rda_binding("farmer_registry", "one");
    second.lookup.input = "sources.first.birth_event_id".to_string();
    claim.source_bindings =
        BTreeMap::from([("first".to_string(), first), ("second".to_string(), second)]);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("dependent source binding cycle must fail validation");
    match err {
        EvidenceConfigError::SourceLookupDependencyCycle { claim, bindings } => {
            assert_eq!(claim, "birth-event");
            assert_eq!(bindings, vec!["first".to_string(), "second".to_string()]);
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn dependent_source_lookup_rejects_self_reference_cycle() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("birth-event");
    let mut solo = rda_binding("farmer_registry", "one");
    solo.lookup.input = "sources.solo.birth_event_id".to_string();
    claim.source_bindings = BTreeMap::from([("solo".to_string(), solo)]);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("self-referential source binding cycle must fail validation");
    match err {
        EvidenceConfigError::SourceLookupDependencyCycle { claim, bindings } => {
            assert_eq!(claim, "birth-event");
            assert_eq!(bindings, vec!["solo".to_string()]);
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn detect_dependency_cycle_accepts_acyclic_chain() {
    let graph = BTreeMap::from([
        ("a".to_string(), BTreeSet::new()),
        ("b".to_string(), BTreeSet::from(["a".to_string()])),
        ("c".to_string(), BTreeSet::from(["b".to_string()])),
    ]);
    assert_eq!(detect_dependency_cycle(&graph), None);
}

#[test]
pub(super) fn detect_dependency_cycle_accepts_diamond_graph() {
    // `d` depends on `b` and `c`, both of which depend on `a`.
    let graph = BTreeMap::from([
        ("a".to_string(), BTreeSet::new()),
        ("b".to_string(), BTreeSet::from(["a".to_string()])),
        ("c".to_string(), BTreeSet::from(["a".to_string()])),
        (
            "d".to_string(),
            BTreeSet::from(["b".to_string(), "c".to_string()]),
        ),
    ]);
    assert_eq!(detect_dependency_cycle(&graph), None);
}

#[test]
pub(super) fn detect_dependency_cycle_reports_three_node_cycle() {
    let graph = BTreeMap::from([
        ("a".to_string(), BTreeSet::from(["c".to_string()])),
        ("b".to_string(), BTreeSet::from(["a".to_string()])),
        ("c".to_string(), BTreeSet::from(["b".to_string()])),
    ]);
    assert_eq!(
        detect_dependency_cycle(&graph),
        Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
    );
}

#[test]
pub(super) fn detect_dependency_cycle_reports_self_reference_after_resolving_others() {
    let graph = BTreeMap::from([
        ("a".to_string(), BTreeSet::new()),
        ("solo".to_string(), BTreeSet::from(["solo".to_string()])),
    ]);
    assert_eq!(
        detect_dependency_cycle(&graph),
        Some(vec!["solo".to_string()])
    );
}

#[test]
pub(super) fn bulk_mode_default_is_none_and_round_trips() {
    let yaml = r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
"#;
    let connection: SourceConnectionConfig =
        serde_norway::from_str(yaml).expect("connection YAML parses");
    assert!(!connection.allow_insecure_localhost);
    assert!(!connection.allow_insecure_private_network);
    assert_eq!(connection.bulk_mode, BulkMode::None);
    assert!(!connection.bulk_mode_lookup_unique);
    assert_eq!(connection.bulk_timeout_max_ms, 30_000);
}

#[test]
pub(super) fn bulk_mode_unknown_variant_is_rejected_at_deserialize() {
    let yaml = r#"
base_url: https://upstream.example
token_env: SRC_TOKEN
bulk_mode: unsupported_mode
"#;
    let err =
        serde_norway::from_str::<SourceConnectionConfig>(yaml).expect_err("unknown variant fails");
    let msg = err.to_string();
    assert!(
        msg.contains("unsupported_mode") || msg.contains("variant") || msg.contains("unknown"),
        "deserialize error mentions the bad variant: {msg}"
    );
}

#[test]
pub(super) fn rda_in_filter_without_unique_attestation_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::RdaInFilter,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("a-claim");
    claim
        .source_bindings
        .insert("farmer".to_string(), rda_binding("farmer_registry", "one"));
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("rda_in_filter without unique attestation must fail");
    match &err {
        EvidenceConfigError::BulkModeRequiresUniqueLookup { connection } => {
            assert_eq!(connection, "farmer_registry");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn rda_in_filter_with_many_cardinality_binding_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::RdaInFilter,
            bulk_mode_lookup_unique: true,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("a-claim");
    claim
        .source_bindings
        .insert("farmer".to_string(), rda_binding("farmer_registry", "many"));
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("rda_in_filter with many-cardinality binding must fail");
    match &err {
        EvidenceConfigError::BulkModeRequiresCardinalityOne {
            connection,
            claim,
            binding,
        } => {
            assert_eq!(connection, "farmer_registry");
            assert_eq!(claim, "a-claim");
            assert_eq!(binding, "farmer");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn dci_batched_search_on_rda_binding_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::DciBatchedSearch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("a-claim");
    claim
        .source_bindings
        .insert("farmer".to_string(), rda_binding("registry", "one"));
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("dci_batched_search on RDA binding must fail");
    match &err {
        EvidenceConfigError::BulkModeRequiresDciConnector {
            connection,
            claim,
            binding,
        } => {
            assert_eq!(connection, "registry");
            assert_eq!(claim, "a-claim");
            assert_eq!(binding, "farmer");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn dci_batched_search_with_dci_bindings_validates() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::DciBatchedSearch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("a-claim");
    claim
        .source_bindings
        .insert("record".to_string(), dci_binding("registry"));
    config.evidence.claims = vec![claim];
    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn query_fields_with_rda_bulk_mode_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::RdaInFilter,
            bulk_mode_lookup_unique: true,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = rda_binding("farmer_registry", "one");
    add_query_fields(&mut binding);
    let mut claim = minimal_claim("a-claim");
    claim.source_bindings.insert("farmer".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("query_fields cannot use rda_in_filter bulk mode");
    match &err {
        EvidenceConfigError::QueryFieldsIncompatibleWithBulkMode {
            connection,
            claim,
            binding,
            bulk_mode,
        } => {
            assert_eq!(connection, "farmer_registry");
            assert_eq!(claim, "a-claim");
            assert_eq!(binding, "farmer");
            assert_eq!(bulk_mode, "rda_in_filter");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn query_fields_with_dci_bulk_mode_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::DciBatchedSearch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = dci_binding("registry");
    add_query_fields(&mut binding);
    let mut claim = minimal_claim("a-claim");
    claim.source_bindings.insert("record".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("query_fields cannot use dci_batched_search bulk mode");
    match &err {
        EvidenceConfigError::QueryFieldsIncompatibleWithBulkMode {
            connection,
            claim,
            binding,
            bulk_mode,
        } => {
            assert_eq!(connection, "registry");
            assert_eq!(claim, "a-claim");
            assert_eq!(binding, "record");
            assert_eq!(bulk_mode, "dci_batched_search");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn query_fields_with_dci_idtype_value_is_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig {
                query_type: "idtype-value".to_string(),
                ..DciSourceConnectionConfig::default()
            },
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = dci_binding("registry");
    add_query_fields(&mut binding);
    let mut claim = minimal_claim("a-claim");
    claim.source_bindings.insert("record".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("query_fields cannot use idtype-value DCI");
    match &err {
        EvidenceConfigError::QueryFieldsIncompatibleWithDciIdTypeValue {
            connection,
            claim,
            binding,
        } => {
            assert_eq!(connection, "registry");
            assert_eq!(claim, "a-claim");
            assert_eq!(binding, "record");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn query_fields_with_dci_expression_validates() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig {
                query_type: "expression".to_string(),
                ..DciSourceConnectionConfig::default()
            },
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = dci_binding("registry");
    add_query_fields(&mut binding);
    let mut claim = minimal_claim("a-claim");
    claim.source_bindings.insert("record".to_string(), binding);
    config.evidence.claims = vec![claim];

    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn source_adapter_sidecar_connector_and_batch_mode_parse_and_validate_with_query_fields()
{
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = source_adapter_sidecar_binding("source_adapter_crvs");
    add_query_fields(&mut binding);
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert("crvs".to_string(), binding);
    config.evidence.claims = vec![claim];

    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn source_adapter_sidecar_yaml_names_parse_and_validate() {
    let raw = r#"
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      fingerprint:
        provider: env
        name: TEST_HASH
      scopes: [civil_registry:evidence_verification]
evidence:
  enabled: true
  service_id: evidence.test
  source_connections:
    source_adapter_crvs:
      base_url: http://127.0.0.1:9191
      allow_insecure_localhost: true
      token_env: SOURCE_ADAPTER_SIDECAR_TOKEN
      retry_on_5xx: false
      bulk_mode: source_adapter_sidecar_batch
      expected_sidecar:
        product: registry-notary-source-adapter-sidecar
        instance_id: demo
        environment: staging
        stream_id: source-adapter-sidecar-runtime
        config_hash: sha256:2222222222222222222222222222222222222222222222222222222222222222
        require_expression_hashes_verified: true
        require_runtime_verified: true
        require_smoke_verified: true
        assurance_ttl_ms: 60000
  claims:
    - id: date-of-birth
      title: Date of birth
      version: 2026-05
      subject_type: person
      source_bindings:
        crvs:
          connector: source_adapter_sidecar
          connection: source_adapter_crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: target.id
            field: national_id
            op: eq
            cardinality: one
          query_fields:
            - input: target.attributes.given_name
              field: given_name
              op: eq
            - input: target.attributes.family_name
              field: family_name
              op: eq
          fields:
            birth_date:
              field: birth_date
              type: string
              required: true
      rule:
        type: extract
        source: crvs
        field: birth_date
      disclosure:
        default: value
        allowed: [value]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#;
    let config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(raw).expect("source-adapter YAML config deserializes");

    assert_eq!(
        config.evidence.source_connections["source_adapter_crvs"].bulk_mode,
        BulkMode::SourceAdapterSidecarBatch
    );
    let expected_sidecar = config.evidence.source_connections["source_adapter_crvs"]
        .expected_sidecar
        .as_ref()
        .expect("expected_sidecar parses");
    assert_eq!(
        expected_sidecar.config_hash,
        "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    );
    assert!(expected_sidecar.require_expression_hashes_verified);
    assert!(expected_sidecar.require_runtime_verified);
    assert!(expected_sidecar.require_smoke_verified);
    assert_eq!(expected_sidecar.assurance_ttl_ms, 60_000);
    assert_eq!(
        config.evidence.claims[0].source_bindings["crvs"].connector,
        SourceConnectorKind::SourceAdapterSidecar
    );
    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn source_adapter_sidecar_expected_sidecar_rejects_invalid_config_hash() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: Some(ExpectedSidecarConfig {
                product: "registry-notary-source-adapter-sidecar".to_string(),
                instance_id: "demo".to_string(),
                environment: "staging".to_string(),
                stream_id: "source-adapter-sidecar-runtime".to_string(),
                config_hash: "sha256:NOTLOWERHEX".to_string(),
                require_expression_hashes_verified: true,
                require_runtime_verified: true,
                require_smoke_verified: true,
                assurance_ttl_ms: 60_000,
            }),
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert(
        "crvs".to_string(),
        source_adapter_sidecar_binding("source_adapter_crvs"),
    );
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("invalid expected_sidecar config_hash must fail");
    match err {
        EvidenceConfigError::InvalidExpectedSidecarConfig { connection, reason } => {
            assert_eq!(connection, "source_adapter_crvs");
            assert!(reason.contains("config_hash"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn source_adapter_sidecar_rejects_oauth_source_auth() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: String::new(),
            source_auth: Some(SourceAuthConfig::Oauth2ClientCredentials(
                Oauth2ClientCredentialsSourceAuthConfig {
                    token_url: "https://sidecar.example/oauth/token".to_string(),
                    client_id_env: "SOURCE_ADAPTER_CLIENT_ID".to_string(),
                    client_secret_env: "SOURCE_ADAPTER_CLIENT_SECRET".to_string(),
                    request_format: "json".to_string(),
                    scope: String::new(),
                    refresh_skew_seconds: 60,
                },
            )),
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert(
        "crvs".to_string(),
        source_adapter_sidecar_binding("source_adapter_crvs"),
    );
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("source-adapter sidecar connections must use token_env auth");
    match err {
        EvidenceConfigError::InvalidSourceAuthConfig { connection, reason } => {
            assert_eq!(connection, "source_adapter_crvs");
            assert!(reason.contains("token_env"));
            assert!(reason.contains("source_adapter_sidecar"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn source_adapter_sidecar_rejects_retry_on_5xx() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert(
        "crvs".to_string(),
        source_adapter_sidecar_binding("source_adapter_crvs"),
    );
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("source-adapter sidecar connections must not retry worker executions");
    match err {
        EvidenceConfigError::SourceAdapterSidecarRequiresNoRetry { connection } => {
            assert_eq!(connection, "source_adapter_crvs");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn source_adapter_sidecar_rejects_non_eq_lookup_operator() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = source_adapter_sidecar_binding("source_adapter_crvs");
    binding.lookup.op = "contains".to_string();
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert("crvs".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("source-adapter sidecar must reject non-eq lookup operators");
    match err {
        EvidenceConfigError::SourceAdapterSidecarUnsupportedOperator { claim, binding, op } => {
            assert_eq!(claim, "date-of-birth");
            assert_eq!(binding, "crvs");
            assert_eq!(op, "contains");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn source_adapter_sidecar_rejects_non_eq_query_field_operator() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "source_adapter_crvs".to_string(),
        SourceConnectionConfig {
            base_url: "http://127.0.0.1:9191".to_string(),
            allow_insecure_localhost: true,
            allow_insecure_private_network: false,
            token_env: "SOURCE_ADAPTER_SIDECAR_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut binding = source_adapter_sidecar_binding("source_adapter_crvs");
    add_query_fields(&mut binding);
    binding.query_fields[1].op = "contains".to_string();
    let mut claim = minimal_claim("date-of-birth");
    claim.source_bindings.insert("crvs".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("source-adapter sidecar must reject non-eq query field operators");
    match err {
        EvidenceConfigError::SourceAdapterSidecarUnsupportedOperator { claim, binding, op } => {
            assert_eq!(claim, "date-of-birth");
            assert_eq!(binding, "crvs");
            assert_eq!(op, "contains");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn rda_in_filter_with_unique_and_cardinality_one_validates() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "farmer_registry".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::RdaInFilter,
            bulk_mode_lookup_unique: true,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("a-claim");
    claim
        .source_bindings
        .insert("farmer".to_string(), rda_binding("farmer_registry", "one"));
    config.evidence.claims = vec![claim];
    assert!(config.validate().is_ok());
}

#[test]
pub(super) fn blank_only_allowed_claims_is_rejected() {
    // `allowed_claims: [""]` would pass an `is_empty()` guard but still
    // fail every issuance with EvaluationBindingMismatch. Treat blank-only
    // lists the same as empty so operators see the error at config load.
    let mut config = minimal_config();
    let profile: CredentialProfileConfig = serde_norway::from_str(
        r#"
format: application/dc+sd-jwt
issuer: https://issuer.example
signing_key: issuer-key
vct: https://vct.example/test
allowed_claims: ["", "   "]
"#,
    )
    .expect("profile YAML is valid");
    config
        .evidence
        .credential_profiles
        .insert("blank_profile".to_string(), profile);

    let err = config
        .validate()
        .expect_err("blank-only allowed_claims must fail validation");
    match &err {
        EvidenceConfigError::EmptyAllowedClaims { profile } => {
            assert_eq!(profile, "blank_profile");
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn blank_evidence_allowed_purpose_is_rejected() {
    let mut config = minimal_config();
    config.evidence.allowed_purposes = vec!["benefits".to_string(), "  ".to_string()];

    let err = config
        .validate()
        .expect_err("blank evidence allowed_purposes must fail validation");

    assert!(matches!(err, EvidenceConfigError::InvalidPurpose));
}

#[test]
pub(super) fn blank_relationship_purpose_scope_entries_are_rejected() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "crvs".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("date-of-birth");
    let binding = rda_binding("crvs", "one");
    claim.source_bindings.insert("src".to_string(), binding);
    claim
        .source_bindings
        .get_mut("src")
        .expect("source binding exists")
        .matching
        .relationship_purpose_scopes
        .insert("guardian".to_string(), vec![" ".to_string()]);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("blank relationship purpose scope must fail validation");

    match err {
        EvidenceConfigError::InvalidMatchingConfig { reason, .. } => {
            assert_eq!(
                reason,
                "relationship_purpose_scopes must contain non-empty relationships and purposes",
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
pub(super) fn relationship_purpose_scope_must_reference_allowed_relationship() {
    let mut config = minimal_config();
    config.evidence.source_connections.insert(
        "crvs".to_string(),
        SourceConnectionConfig {
            base_url: "https://upstream.example".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: "SRC_TOKEN".to_string(),
            source_auth: None,
            expected_sidecar: None,
            dci: DciSourceConnectionConfig::default(),
            max_in_flight: 8,
            retry_on_5xx: true,
            bulk_mode: BulkMode::None,
            bulk_mode_lookup_unique: false,
            bulk_timeout_max_ms: 30_000,
        },
    );
    let mut claim = minimal_claim("date-of-birth");
    let mut binding = rda_binding("crvs", "one");
    binding
        .matching
        .relationship_purpose_scopes
        .insert("guardian".to_string(), vec!["benefits".to_string()]);
    claim.source_bindings.insert("src".to_string(), binding);
    config.evidence.claims = vec![claim];

    let err = config
        .validate()
        .expect_err("scope relationship must be in the flat allow-list");

    match err {
        EvidenceConfigError::InvalidMatchingConfig { reason, .. } => {
            assert_eq!(
                reason,
                "relationship_purpose_scopes entries must also appear in allowed_relationships",
            );
        }
        other => panic!("unexpected error variant: {other}"),
    }
}
