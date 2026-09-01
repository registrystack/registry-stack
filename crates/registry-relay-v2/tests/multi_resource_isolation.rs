// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, LINK};
use http::{Method, Request, StatusCode};
use jsonschema::{Draft, JSONSchema};
use registry_platform_audit::{AuditChainHasher, AuditEnvelope, AuditError, AuditSink, ChainState};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier};
use registry_platform_sqlite::{
    inspect_schema, materialize_fixture, CapturedSnapshot, DatabaseProfile, InspectionLimits,
    SchemaObjectKind,
};
use registry_platform_testing::{
    fixtures, oidc_verifier_config, sign_ed25519_compact_jwt, MockIdp,
};
use registry_relay_v2::artifacts::{generate_artifacts, ArtifactSet};
use registry_relay_v2::audit::RelayAudit;
use registry_relay_v2::auth::RelayAuthenticator;
use registry_relay_v2::compiler::{
    classification_inventory_digest, compile_contract, compile_contract_with_governed_files,
    GovernedFileSet,
};
use registry_relay_v2::contract::{RegistryContract, Visibility};
use registry_relay_v2::cursor::CursorKey;
use registry_relay_v2::model::{
    CompileProfile, CompiledAccess, CompiledRegistry, ObservedColumn, ObservedSourceSchema,
    ObservedView, OperationKind, RowAuthoritySource,
};
use registry_relay_v2::server::{
    router, AlignmentMetadata, InstitutionMetadata, QuotaConfig, RelayService, ServiceMetadata,
};
use registry_relay_v2::sqlite_runtime::{RuntimeSourceBinding, SqliteRuntime, SqliteRuntimeLimits};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt as _;

const REGISTRY_ID: &str = "urn:example:registry:cross-product-conformance";
const SOURCE_ID: &str = "synthetic-source";
const PUBLIC_RESOURCE: &str = "public-unit";
const PROTECTED_RESOURCE: &str = "protected-unit";
const PUBLIC_RECORD_ID: &str = "10000000-0000-4000-8000-000000000001";
const PROTECTED_RECORD_ID: &str = "20000000-0000-4000-8000-000000000001";
const REGISTRY_RECORD_PROFILE_ID: &str = "https://id.registrystack.org/profiles/registry-record/v1";
const REGISTRY_RECORD_CONTEXT_ID: &str = "https://id.registrystack.org/contexts/registry-record/v1";

const FIXTURE_SQL: &str = r#"
CREATE TABLE public_rows (
    unit_id TEXT PRIMARY KEY NOT NULL,
    revision TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    public_label TEXT NOT NULL
) STRICT;

INSERT INTO public_rows VALUES
('10000000-0000-4000-8000-000000000001', '1', 'ACTIVE', '2026-08-01T00:00:00Z', 'PUBLIC-SEMANTIC-CANARY');

CREATE TABLE protected_rows (
    unit_id TEXT PRIMARY KEY NOT NULL,
    revision TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    protected_label TEXT NOT NULL,
    lookup_key TEXT NOT NULL,
    authority_key TEXT NOT NULL
) STRICT;

INSERT INTO protected_rows VALUES
('20000000-0000-4000-8000-000000000001', '1', 'ACTIVE', '2026-08-02T00:00:00Z', 'PROTECTED-SEMANTIC-CANARY', 'lookup-a1', 'zone-a'),
('protected-002', 'protected-r2', 'ACTIVE', '2026-08-03T00:00:00Z', 'PROTECTED-CANARY-A2', 'lookup-a2', 'zone-a'),
('protected-003', 'protected-r3', 'ACTIVE', '2026-08-04T00:00:00Z', 'PROTECTED-CANARY-B1', 'lookup-b1', 'zone-b');

CREATE VIEW relay_public_units AS
SELECT unit_id, revision, lifecycle, recorded_at, public_label
FROM public_rows;

CREATE VIEW relay_protected_units AS
SELECT unit_id, revision, lifecycle, recorded_at, protected_label, lookup_key, authority_key
FROM protected_rows;
"#;

const CONTRACT_YAML: &str = r#"
apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata:
  id: synthetic-related-units
  version: "1"
  title: Synthetic related units
registry:
  registryIdentifier: urn:example:registry:cross-product-conformance
  name: Synthetic unit Registry
  authority: {identifier: urn:example:institution:unit-authority, name: Unit Authority}
  operator: {identifier: urn:example:institution:unit-operator, name: Unit Operator}
  authoritativeScope: Synthetic related units used to prove resource isolation
  baseUri: https://units.example.invalid/registry/
  identifierLifecyclePolicyRef: governance/identifier-lifecycle.yaml
  alignmentTargets:
    - name: synthetic-registry-profile
      version: "1"
      status: directional
governance:
  controller: urn:example:institution:unit-controller
  publisher: urn:example:institution:unit-publisher
  auditOwner: urn:example:institution:unit-audit
semantics:
  localVocabulary: https://units.example.invalid/vocabulary/
  alignments: []
classifications:
  privacy: {scheme: https://example.invalid/privacy, version: "1"}
  institutional: {scheme: https://example.invalid/institutional, version: "1"}
  handling: {scheme: https://id.registrystack.org/vocab/handling, version: "1"}
  provenanceRef: governance/classification-provenance.yaml
sources:
  synthetic-source:
    kind: sqlite
    profile: snapshot
    expectedSchemaFingerprint: OBSERVED_FINGERPRINT
resources:
  - id: public-unit
    datasetIdentifier: public-units
    entityTypeIdentifier: public-unit
    title: Public unit
    description: Public projection of a synthetic related unit.
    semanticClass: local:PublicUnit
    source: {source: synthetic-source, view: relay_public_units}
    classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: reviewed}
    recordContext:
      recordIdentifier: {sourceColumn: unit_id}
      revisionIdentifier: {sourceColumn: revision}
      lifecycleState: {sourceColumn: lifecycle, codelist: codelists/lifecycle.yaml}
      recordedAt: {sourceColumn: recorded_at}
    properties:
      publicIdentifier:
        sourceColumn: unit_id
        type: string
        sourceRequired: true
        semanticTerm: local:publicIdentifier
        label: Public identifier
        description: Stable public unit identifier.
      label:
        sourceColumn: public_label
        type: string
        sourceRequired: true
        semanticTerm: local:label
        label: Public label
        description: Public synthetic label.
    disclosureProfiles:
      public-view: {properties: [label]}
    operations:
      list:
        defaultAccessProfile: public
        accessProfiles:
          public: {access: public, disclosureProfile: public-view}
        filters: []
        allowUnfiltered: true
        orderBy: [publicIdentifier]
        pagination: {defaultPageSize: 1, maximumPageSize: 1}
      read:
        defaultAccessProfile: public
        accessProfiles:
          public: {access: public, disclosureProfile: public-view}
    processingDescriptions: []
  - id: protected-unit
    datasetIdentifier: protected-units
    entityTypeIdentifier: protected-unit
    title: Protected unit
    description: Protected projection of a synthetic related unit.
    semanticClass: local:ProtectedUnit
    source: {source: synthetic-source, view: relay_protected_units}
    classificationDefaults: {privacy: non-personal, institutional: internal, handling: internal, status: reviewed}
    sourceColumnClassifications:
      lookup_key: {privacy: non-personal}
      authority_key: {privacy: non-personal}
    recordContext:
      recordIdentifier: {sourceColumn: unit_id}
      revisionIdentifier: {sourceColumn: revision}
      lifecycleState: {sourceColumn: lifecycle, codelist: codelists/lifecycle.yaml}
      recordedAt: {sourceColumn: recorded_at}
    properties:
      protectedIdentifier:
        sourceColumn: unit_id
        type: string
        sourceRequired: true
        semanticTerm: local:protectedIdentifier
        label: Protected identifier
        description: Stable protected unit identifier.
      label:
        sourceColumn: protected_label
        type: string
        sourceRequired: true
        semanticTerm: local:label
        label: Protected label
        description: Protected synthetic label.
    disclosureProfiles:
      protected-view: {properties: [label]}
    operations:
      list:
        defaultAccessProfile: protected
        accessProfiles:
          protected:
            access:
              scope: relay:protected:list
              purpose: {claim: purpose, allowed: [bounded-read]}
              authorityRowBinding: {claim: authority, sourceColumn: authority_key}
            disclosureProfile: protected-view
        filters: []
        allowUnfiltered: true
        orderBy: [protectedIdentifier]
        pagination: {defaultPageSize: 2, maximumPageSize: 2}
      read:
        defaultAccessProfile: protected
        accessProfiles:
          protected:
            access:
              scope: relay:protected:read
              purpose: {claim: purpose, allowed: [bounded-read]}
              authorityRowBinding: {claim: authority, sourceColumn: authority_key}
            disclosureProfile: protected-view
      lookups:
        - id: by-key
          requestBody:
            maximumBytes: 128
            selectors:
              lookupKey: {sourceColumn: lookup_key, type: string, minimumBytes: 1, maximumBytes: 32}
          defaultAccessProfile: protected
          accessProfiles:
            protected:
              access:
                scope: relay:protected:lookup
                purpose: {claim: purpose, allowed: [bounded-read]}
                authorityRowBinding: {claim: authority, sourceColumn: authority_key}
              disclosureProfile: protected-view
    processingDescriptions:
      - id: protected-consultation
        operationRefs: [list, read, lookup:by-key]
        purpose: bounded-read
        recipientClass: authorized-service
        legalBasisRef: governance/legal-basis.yaml
        dpvProfileRef: governance/processing.dpv.yaml
        safeguards: [property-minimization, authority-row-binding]
metadataVisibility:
  service: public
  resources: public
  semantics: public
  classifications: operator-only
  processing: operator-only
"#;

struct Fixture {
    _temp: TempDir,
    database: std::path::PathBuf,
    contract: RegistryContract,
    compiled: Arc<CompiledRegistry>,
    artifacts: Arc<ArtifactSet>,
}

#[derive(Default)]
struct RecordingAuditSink {
    envelopes: Mutex<Vec<AuditEnvelope>>,
}

impl RecordingAuditSink {
    fn records(&self) -> Vec<Value> {
        self.envelopes
            .lock()
            .expect("audit recorder lock")
            .iter()
            .map(|envelope| envelope.record.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl AuditSink for RecordingAuditSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        self.envelopes
            .lock()
            .expect("audit recorder lock")
            .push(envelope.clone());
        Ok(())
    }

    #[allow(deprecated)]
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(self
            .envelopes
            .lock()
            .expect("audit recorder lock")
            .last()
            .map(|envelope| envelope.record_hash))
    }

    async fn tail_hash_with_hasher(
        &self,
        _hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(self
            .envelopes
            .lock()
            .expect("audit recorder lock")
            .last()
            .map(|envelope| envelope.record_hash))
    }
}

#[test]
fn compiler_keeps_every_multi_resource_operation_boundary_local() {
    let fixture = compile_fixture();
    assert_eq!(fixture.compiled.resources.len(), 2);

    let cases = [
        (
            PUBLIC_RESOURCE,
            "relay_public_units",
            "public-view",
            "label",
            1,
            None,
            None,
        ),
        (
            PROTECTED_RESOURCE,
            "relay_protected_units",
            "protected-view",
            "label",
            2,
            Some("relay:protected:list"),
            Some("authority_key"),
        ),
    ];
    for (resource_id, view, disclosure, field, page_maximum, scope, row_column) in cases {
        let resource = resource(&fixture.compiled, resource_id);
        assert_eq!(resource.source, SOURCE_ID);
        assert_eq!(resource.view, view);
        let list = operation(resource, "list");
        assert_eq!(list.identifier, format!("{resource_id}.list"));
        assert_eq!(list.query.source, SOURCE_ID);
        assert_eq!(list.query.view, view);
        let access_profile = list
            .access_profiles
            .iter()
            .find(|access_profile| access_profile.id == list.default_access_profile)
            .expect("default access profile is compiled");
        assert_eq!(access_profile.disclosure_profile, disclosure);
        assert_eq!(access_profile.selectable_properties, [field]);
        assert_eq!(
            list.query
                .pagination
                .as_ref()
                .expect("list has pagination")
                .maximum_page_size,
            page_maximum
        );
        match (&access_profile.access, scope, row_column) {
            (CompiledAccess::Public, None, None) => {}
            (
                CompiledAccess::Protected {
                    scope: actual_scope,
                    row_binding: Some(binding),
                    ..
                },
                Some(expected_scope),
                Some(expected_column),
            ) => {
                assert_eq!(actual_scope, expected_scope);
                assert_eq!(binding.source_column, expected_column);
                assert!(
                    matches!(binding.source, RowAuthoritySource::Claim(ref claim) if claim == "authority")
                );
            }
            boundary => panic!("unexpected compiled access boundary: {boundary:?}"),
        }
        assert!(access_profile.schema_reference.contains(resource_id));
        assert!(access_profile
            .semantic_model_reference
            .contains(resource_id));
    }

    let protected = resource(&fixture.compiled, PROTECTED_RESOURCE);
    let lookup = operation(protected, "lookup");
    assert_eq!(lookup.identifier, "protected-unit.lookup.by-key");
    assert_eq!(lookup.query.view, "relay_protected_units");
    assert_eq!(lookup.query.maximum_request_body_bytes, Some(128));
    assert_eq!(
        lookup
            .query
            .selectors
            .iter()
            .map(|selector| selector.name.as_str())
            .collect::<Vec<_>>(),
        ["lookupKey"]
    );

    let public_capabilities = artifact_json(&fixture.artifacts, "artifacts/capabilities.json");
    let full_capabilities = artifact_json(&fixture.artifacts, "artifacts/capabilities.full.json");
    assert_eq!(
        capability_ids(&public_capabilities),
        BTreeSet::from(["public-unit.list", "public-unit.read"])
    );
    assert_eq!(
        capability_ids(&full_capabilities),
        BTreeSet::from([
            "protected-unit.list",
            "protected-unit.lookup.by-key",
            "protected-unit.read",
            "public-unit.list",
            "public-unit.read",
        ])
    );

    let public_openapi = artifact_text(&fixture.artifacts, "openapi.public.json");
    let full_openapi = artifact_text(&fixture.artifacts, "openapi.full.yaml");
    assert!(public_openapi.contains("/v2/resources/public-unit/records"));
    assert!(!public_openapi.contains("protected-unit"));
    assert!(!public_openapi.contains("lookupKey"));
    assert!(full_openapi.contains("/v2/resources/protected-unit/records"));
    assert!(full_openapi.contains("lookupKey"));

    for artifact in fixture.artifacts.artifacts.iter().filter(|artifact| {
        (artifact.id.starts_with("protected-unit-") || artifact.id.starts_with("protected-unit."))
            && (artifact.id.ends_with("-capability")
                || artifact.id.ends_with("-classifications")
                || artifact.id.ends_with("-processing"))
    }) {
        assert_ne!(
            artifact.visibility,
            Visibility::Public,
            "a public sibling must not make protected resource artifact {} public",
            artifact.id
        );
    }
}

#[tokio::test]
async fn real_router_keeps_related_public_and_protected_resources_isolated() {
    let fixture = compile_fixture();
    let sink = Arc::new(RecordingAuditSink::default());
    let chain = Arc::new(
        ChainState::bootstrap_unkeyed_dev_only(sink.as_ref())
            .await
            .expect("audit chain starts"),
    );
    let idp = MockIdp::start().await;
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    fetcher.ensure_key_set().await.expect("fixture JWKS loads");
    let audience = "urn:example:relay:synthetic-units";
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![audience.into()]);
    verifier.allowed_typ = vec!["at+jwt".into()];
    verifier.max_token_lifetime = Some(Duration::from_secs(3600));
    let authenticator = RelayAuthenticator::new(
        Arc::new(TokenVerifier::new(verifier.clone(), Arc::clone(&fetcher))),
        audience.into(),
        Duration::from_secs(30),
    );
    let sqlite = Arc::new(
        SqliteRuntime::open(
            &fixture.compiled,
            &BTreeMap::from([(
                SOURCE_ID.to_owned(),
                RuntimeSourceBinding {
                    path: fixture.database.clone(),
                },
            )]),
            SqliteRuntimeLimits {
                request_timeout: Duration::from_secs(5),
                concurrent_queries: 2,
            },
        )
        .expect("SQLite runtime opens"),
    );
    let service = Arc::new(RelayService::new(
        Arc::clone(&fixture.compiled),
        Arc::clone(&fixture.artifacts),
        Arc::clone(&sqlite),
        Some(authenticator),
        RelayAudit::new(Arc::clone(&chain), sink.clone()),
        Some(Arc::new(
            CursorKey::new(vec![7; 32]).expect("fixture cursor key is valid"),
        )),
        Duration::from_secs(300),
        Duration::from_secs(5),
        Some(QuotaConfig {
            requests_per_minute: 1,
            burst: 1,
        }),
        service_metadata(&fixture),
    ));
    let app = router(service);
    let conformance_service = Arc::new(RelayService::new(
        Arc::clone(&fixture.compiled),
        Arc::clone(&fixture.artifacts),
        sqlite,
        Some(RelayAuthenticator::new(
            Arc::new(TokenVerifier::new(verifier, fetcher)),
            audience.into(),
            Duration::from_secs(30),
        )),
        RelayAudit::new(Arc::clone(&chain), sink.clone()),
        Some(Arc::new(
            CursorKey::new(vec![8; 32]).expect("fixture cursor key is valid"),
        )),
        Duration::from_secs(300),
        Duration::from_secs(5),
        None,
        service_metadata(&fixture),
    ));
    let conformance_app = router(conformance_service);

    let all_scopes = BTreeSet::from([
        "relay:protected:list",
        "relay:protected:lookup",
        "relay:protected:read",
    ]);
    let allowed = token(
        &idp,
        audience,
        "allowed",
        all_scopes.clone(),
        [("purpose", "bounded-read"), ("authority", "zone-a")],
    );
    let wrong_scope = token(
        &idp,
        audience,
        "wrong-scope",
        BTreeSet::from(["relay:protected:read"]),
        [("purpose", "bounded-read"), ("authority", "zone-a")],
    );
    let denied_read = token(
        &idp,
        audience,
        "denied-read",
        BTreeSet::from(["relay:protected:list"]),
        [("purpose", "bounded-read"), ("authority", "zone-a")],
    );
    let missing_binding = token(
        &idp,
        audience,
        "missing-binding",
        all_scopes,
        [("purpose", "bounded-read")],
    );

    assert_problem(
        send(
            &app,
            Method::GET,
            "/v2/resources/public-unit/records?pageSize=2",
            None,
            None,
            "00000000000000000000000000000001",
        )
        .await,
        StatusCode::BAD_REQUEST,
        "consultation.invalid_request",
    );
    assert_problem(
        send(
            &app,
            Method::GET,
            "/v2/resources/protected-unit/records?pageSize=2",
            None,
            None,
            "00000000000000000000000000000002",
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "auth.missing_credential",
    );
    assert_problem(
        send(
            &app,
            Method::GET,
            "/v2/resources/protected-unit/records?pageSize=2",
            Some(&wrong_scope),
            None,
            "00000000000000000000000000000003",
        )
        .await,
        StatusCode::NOT_FOUND,
        "resource.not_found",
    );
    assert_problem(
        send(
            &app,
            Method::GET,
            "/v2/resources/protected-unit/records?pageSize=2",
            Some(&missing_binding),
            None,
            "00000000000000000000000000000004",
        )
        .await,
        StatusCode::FORBIDDEN,
        "consultation.denied",
    );

    let public_read = assert_success(
        send(
            &app,
            Method::GET,
            &format!("/v2/resources/public-unit/records/{PUBLIC_RECORD_ID}"),
            None,
            None,
            "00000000000000000000000000000005",
        )
        .await,
    );
    assert_record_state(
        &public_read,
        "public-unit.read",
        "public-view",
        "label",
        "PUBLIC-SEMANTIC-CANARY",
    );
    assert!(!public_read.to_string().contains("PROTECTED-CANARY"));

    assert_problem(
        send(
            &app,
            Method::GET,
            &format!("/v2/resources/protected-unit/records/{PROTECTED_RECORD_ID}"),
            None,
            None,
            "00000000000000000000000000000006",
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "auth.missing_credential",
    );
    let protected_read = assert_success(
        send(
            &app,
            Method::GET,
            &format!("/v2/resources/protected-unit/records/{PROTECTED_RECORD_ID}"),
            Some(&allowed),
            None,
            "00000000000000000000000000000007",
        )
        .await,
    );
    assert_record_state(
        &protected_read,
        "protected-unit.read",
        "protected-view",
        "label",
        "PROTECTED-SEMANTIC-CANARY",
    );
    assert!(!protected_read
        .to_string()
        .contains("PUBLIC-SEMANTIC-CANARY"));

    let protected_list = assert_success(
        send(
            &app,
            Method::GET,
            "/v2/resources/protected-unit/records?pageSize=2",
            Some(&allowed),
            None,
            "00000000000000000000000000000008",
        )
        .await,
    );
    let items = protected_list["items"].as_array().expect("list items");
    assert_eq!(items.len(), 2);
    assert_eq!(
        items
            .iter()
            .filter_map(|item| item["domainData"]["label"].as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["PROTECTED-CANARY-A2", "PROTECTED-SEMANTIC-CANARY"])
    );
    assert!(!protected_list.to_string().contains("CANARY-B"));

    assert_problem(
        send(
            &app,
            Method::GET,
            &format!(
                "/v2/resources/protected-unit/records/{PROTECTED_RECORD_ID}?fields=publicLabel"
            ),
            Some(&allowed),
            None,
            "00000000000000000000000000000009",
        )
        .await,
        StatusCode::BAD_REQUEST,
        "request.fields_invalid",
    );
    assert_problem(
        send(
            &app,
            Method::POST,
            "/v2/resources/public-unit/lookups/by-key",
            Some(&allowed),
            Some(json!({"selectors": {"lookupKey": "lookup-a1"}})),
            "0000000000000000000000000000000a",
        )
        .await,
        StatusCode::NOT_FOUND,
        "resource.not_found",
    );
    let lookup = assert_success(
        send(
            &app,
            Method::POST,
            "/v2/resources/protected-unit/lookups/by-key",
            Some(&allowed),
            Some(json!({"selectors": {"lookupKey": "lookup-a1"}})),
            "0000000000000000000000000000000b",
        )
        .await,
    );
    assert_record_state(
        &lookup,
        "protected-unit.lookup.by-key",
        "protected-view",
        "label",
        "PROTECTED-SEMANTIC-CANARY",
    );
    assert_problem(
        send_raw_body(
            &app,
            Method::POST,
            "/v2/resources/protected-unit/lookups/by-key",
            Some(&allowed),
            b"not-json",
            "0000000000000000000000000000000d",
        )
        .await,
        StatusCode::TOO_MANY_REQUESTS,
        "consultation.rate_limited",
    );
    let independent_public_list = assert_success(
        send(
            &app,
            Method::GET,
            "/v2/resources/public-unit/records?pageSize=1",
            None,
            None,
            "0000000000000000000000000000000e",
        )
        .await,
    );
    assert_eq!(
        independent_public_list["items"]
            .as_array()
            .expect("public list items")
            .len(),
        1,
        "one exhausted protected lookup bucket cannot starve another resource operation"
    );

    let metadata = assert_success(
        send(
            &app,
            Method::GET,
            "/v2",
            None,
            None,
            "0000000000000000000000000000000c",
        )
        .await,
    );
    assert_eq!(metadata["registryIdentifier"], REGISTRY_ID);
    assert_eq!(
        metadata["capabilities"]
            .as_array()
            .expect("service capabilities")
            .iter()
            .filter_map(|capability| capability["operationIdentifier"].as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["public-unit.list", "public-unit.read"])
    );
    assert!(!metadata.to_string().contains(PROTECTED_RESOURCE));

    let gold = semantic_gold();
    assert_matches_semantic_gold(&public_read, &gold, "public");
    assert_matches_semantic_gold(&protected_read, &gold, "protected");

    let public_json_ld = assert_success_with_headers(
        send_representation(
            &conformance_app,
            Method::GET,
            &format!("/v2/resources/public-unit/records/{PUBLIC_RECORD_ID}"),
            None,
            "application/ld+json",
            "0000000000000000000000000000000f",
        )
        .await,
    );
    assert_profile_link(&public_json_ld.1);
    assert_eq!(
        public_json_ld.2["@context"],
        json!([
            REGISTRY_RECORD_CONTEXT_ID,
            public_json_ld.2["meta"]["links"]["context"].clone()
        ])
    );
    assert_matches_semantic_gold(&public_json_ld.2, &gold, "public");
    assert!(public_json_ld.2["data"].get("@id").is_some());
    assert!(public_json_ld.2["data"].get("@type").is_some());

    let protected_json_ld = assert_success_with_headers(
        send_representation(
            &conformance_app,
            Method::GET,
            &format!("/v2/resources/protected-unit/records/{PROTECTED_RECORD_ID}"),
            Some(&allowed),
            "application/ld+json",
            "00000000000000000000000000000010",
        )
        .await,
    );
    assert_profile_link(&protected_json_ld.1);
    assert_matches_semantic_gold(&protected_json_ld.2, &gold, "protected");

    let public_list_json_ld = assert_success_with_headers(
        send_representation(
            &conformance_app,
            Method::GET,
            "/v2/resources/public-unit/records?pageSize=1",
            None,
            "application/ld+json",
            "00000000000000000000000000000011",
        )
        .await,
    );
    assert_profile_link(&public_list_json_ld.1);
    assert_collection_matches_semantic_gold(&public_list_json_ld.2, &gold, "public");
    assert!(public_list_json_ld.2["items"][0].get("@id").is_some());
    assert!(public_list_json_ld.2["items"][0].get("@type").is_some());

    let public_json_schema =
        exact_generated_response_schema(&fixture.artifacts, "public-unit.read", "application/json");
    let public_json_ld_schema = exact_generated_response_schema(
        &fixture.artifacts,
        "public-unit.read",
        "application/ld+json",
    );
    let public_list_schema =
        exact_generated_response_schema(&fixture.artifacts, "public-unit.list", "application/json");
    let public_list_json_ld_schema = exact_generated_response_schema(
        &fixture.artifacts,
        "public-unit.list",
        "application/ld+json",
    );
    assert!(public_json_schema.is_valid(&public_read));
    assert!(public_json_ld_schema.is_valid(&public_json_ld.2));
    assert!(public_list_schema.is_valid(&independent_public_list));
    assert!(public_list_json_ld_schema.is_valid(&public_list_json_ld.2));
    assert_meta_constant_mutations_are_rejected(&public_json_schema, &public_read);

    let protected_json_schema = exact_generated_response_schema(
        &fixture.artifacts,
        "protected-unit.read",
        "application/json",
    );
    assert!(protected_json_schema.is_valid(&protected_read));
    assert_meta_constant_mutations_are_rejected(&protected_json_schema, &protected_read);

    let shared = shared_base_validator();
    for document in [
        &public_read,
        &public_json_ld.2,
        &independent_public_list,
        &public_list_json_ld.2,
        &protected_read,
    ] {
        assert!(shared.is_valid(document));
    }
    let mut base_extension = public_read.clone();
    base_extension["data"]["domainData"]["productExtension"] = json!("base-open");
    assert!(shared.is_valid(&base_extension));
    assert!(!public_json_schema.is_valid(&base_extension));

    let public_resources = assert_success_with_headers(
        send_representation(
            &conformance_app,
            Method::GET,
            "/v2/resources",
            None,
            "application/json",
            "00000000000000000000000000000012",
        )
        .await,
    );
    let public_openapi = assert_success_with_headers(
        send_representation(
            &conformance_app,
            Method::GET,
            "/openapi.json",
            None,
            "application/json",
            "00000000000000000000000000000013",
        )
        .await,
    );
    for public_document in [&public_resources.2, &public_openapi.2] {
        let rendered = public_document.to_string();
        assert!(rendered.contains(PUBLIC_RESOURCE));
        for absent in [
            PROTECTED_RESOURCE,
            "protected-units",
            "PROTECTED-SEMANTIC-CANARY",
        ] {
            assert!(
                !rendered.contains(absent),
                "public discovery disclosed {absent}"
            );
        }
    }

    let insufficient = send(
        &conformance_app,
        Method::GET,
        &format!("/v2/resources/protected-unit/records/{PROTECTED_RECORD_ID}"),
        Some(&denied_read),
        None,
        "00000000000000000000000000000014",
    )
    .await;
    let unknown = send(
        &conformance_app,
        Method::GET,
        &format!("/v2/resources/unknown-unit/records/{PROTECTED_RECORD_ID}"),
        Some(&denied_read),
        None,
        "00000000000000000000000000000015",
    )
    .await;
    assert_concealed_equivalence(insufficient, unknown);

    let audits = sink.records();
    assert_audit_boundary(
        &audits,
        "00000000000000000000000000000005",
        PUBLIC_RESOURCE,
        "public-unit.read",
        "public-view",
        "none",
        "label",
    );
    assert_audit_boundary(
        &audits,
        "00000000000000000000000000000007",
        PROTECTED_RESOURCE,
        "protected-unit.read",
        "protected-view",
        "verified-claim",
        "label",
    );
    assert_audit_boundary(
        &audits,
        "00000000000000000000000000000008",
        PROTECTED_RESOURCE,
        "protected-unit.list",
        "protected-view",
        "verified-claim",
        "label",
    );
    assert_audit_boundary(
        &audits,
        "0000000000000000000000000000000b",
        PROTECTED_RESOURCE,
        "protected-unit.lookup.by-key",
        "protected-view",
        "verified-claim",
        "label",
    );
    let audit_text = serde_json::to_string(&audits).expect("audits serialize");
    for absent in [
        "PUBLIC-SEMANTIC-CANARY",
        "PROTECTED-SEMANTIC-CANARY",
        "PROTECTED-CANARY",
        "lookup-a1",
        "zone-a",
        "synthetic-caller",
    ] {
        assert!(!audit_text.contains(absent), "audit disclosed {absent}");
    }

    idp.stop().await;
}

fn service_metadata(fixture: &Fixture) -> ServiceMetadata {
    ServiceMetadata {
        authority: InstitutionMetadata {
            identifier: fixture.contract.registry.authority.identifier.clone(),
            name: fixture.contract.registry.authority.name.clone(),
        },
        operator: fixture
            .contract
            .registry
            .operator
            .as_ref()
            .map(|operator| InstitutionMetadata {
                identifier: operator.identifier.clone(),
                name: operator.name.clone(),
            }),
        authoritative_scope: fixture.contract.registry.authoritative_scope.clone(),
        alignment_targets: fixture
            .contract
            .registry
            .alignment_targets
            .iter()
            .map(|target| AlignmentMetadata {
                name: target.name.clone(),
                version: target.version.clone(),
                status: target.status.clone(),
                cfr_target: target.cfr_target.clone(),
            })
            .collect(),
    }
}

fn compile_fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let database = temp.path().join("multi-resource.sqlite");
    materialize_fixture(&database, FIXTURE_SQL).expect("fixture database materializes");
    let captured = CapturedSnapshot::capture(&database).expect("fixture snapshot captures");
    let catalog = inspect_schema(
        &DatabaseProfile::Snapshot(captured),
        &InspectionLimits {
            maximum_objects: 100,
            maximum_sql_bytes: 128 * 1024,
            maximum_statement_steps: 100_000,
            timeout: Duration::from_secs(5),
        },
    )
    .expect("fixture schema inspects");
    let contract_text = CONTRACT_YAML.replace("OBSERVED_FINGERPRINT", &catalog.fingerprint);
    let contract = RegistryContract::parse_yaml(&contract_text).expect("contract parses");
    let observed = vec![ObservedSourceSchema {
        source: SOURCE_ID.into(),
        fingerprint: catalog.fingerprint,
        views: catalog
            .objects
            .into_iter()
            .filter(|object| object.kind == SchemaObjectKind::View)
            .map(|object| ObservedView {
                name: object.name,
                columns: object
                    .columns
                    .into_iter()
                    .map(|column| ObservedColumn {
                        name: column.name,
                        declared_type: column.declared_type,
                        nullable: column.nullable,
                        primary_key: column.primary_key,
                    })
                    .collect(),
            })
            .collect(),
    }];
    let inventory = compile_contract(&contract, &observed, CompileProfile::Production)
        .expect("classification inventory compiles");
    let inventory_digest =
        classification_inventory_digest(&inventory).expect("classification inventory digests");
    let review = format!(
        "apiVersion: relay.registrystack.org/classification-review/v1\nkind: ClassificationReview\nregistryIdentifier: {REGISTRY_ID}\nclassificationInventoryDigest: {inventory_digest}\nmethod: manual\nreviewer: urn:example:institution:unit-authority\nreviewDate: 2026-08-10\nstatus: reviewed\nrationaleRef: governance/classification-review-rationale.md\n"
    );
    let governed = GovernedFileSet::from([
        (
            "governance/identifier-lifecycle.yaml".into(),
            b"kind: synthetic-policy\n".to_vec(),
        ),
        (
            "governance/classification-provenance.yaml".into(),
            review.into_bytes(),
        ),
        (
            "governance/classification-review-rationale.md".into(),
            b"Synthetic multi-resource classification review.\n".to_vec(),
        ),
        (
            "codelists/lifecycle.yaml".into(),
            b"id: synthetic-lifecycle\nversion: '1'\nvalues: [ACTIVE]\nstatus: reviewed\n".to_vec(),
        ),
        (
            "governance/legal-basis.yaml".into(),
            b"status: reviewed\nbasis: synthetic-authority\n".to_vec(),
        ),
        (
            "governance/processing.dpv.yaml".into(),
            b"status: reviewed\nprofile: https://w3id.org/dpv/2.3\n".to_vec(),
        ),
    ]);
    let compiled = Arc::new(
        compile_contract_with_governed_files(
            &contract,
            &observed,
            CompileProfile::Production,
            &governed,
        )
        .unwrap_or_else(|report| panic!("multi-resource contract compiles: {report:?}")),
    );
    let artifacts = Arc::new(generate_artifacts(&compiled).expect("artifacts generate"));
    Fixture {
        _temp: temp,
        database,
        contract,
        compiled,
        artifacts,
    }
}

fn resource<'a>(
    registry: &'a CompiledRegistry,
    id: &str,
) -> &'a registry_relay_v2::model::CompiledResource {
    registry
        .resources
        .iter()
        .find(|resource| resource.id == id)
        .unwrap_or_else(|| panic!("resource {id} is compiled"))
}

fn operation<'a>(
    resource: &'a registry_relay_v2::model::CompiledResource,
    kind: &str,
) -> &'a registry_relay_v2::model::CompiledOperation {
    resource
        .operations
        .iter()
        .find(|operation| {
            matches!(
                (&operation.kind, kind),
                (OperationKind::List, "list")
                    | (OperationKind::Read, "read")
                    | (OperationKind::Lookup { .. }, "lookup")
            )
        })
        .unwrap_or_else(|| panic!("{kind} operation is compiled for {}", resource.id))
}

fn artifact_json(artifacts: &ArtifactSet, path: &str) -> Value {
    serde_json::from_slice(
        &artifacts
            .get(path)
            .unwrap_or_else(|| panic!("artifact {path} exists"))
            .content,
    )
    .unwrap_or_else(|error| panic!("artifact {path} is JSON: {error}"))
}

fn artifact_text<'a>(artifacts: &'a ArtifactSet, path: &str) -> &'a str {
    std::str::from_utf8(
        &artifacts
            .get(path)
            .unwrap_or_else(|| panic!("artifact {path} exists"))
            .content,
    )
    .unwrap_or_else(|error| panic!("artifact {path} is UTF-8: {error}"))
}

fn capability_ids(document: &Value) -> BTreeSet<&str> {
    document["capabilities"]
        .as_array()
        .expect("capability array")
        .iter()
        .filter_map(|capability| capability["operationIdentifier"].as_str())
        .collect()
}

fn token<const N: usize>(
    idp: &MockIdp,
    audience: &str,
    fixture: &str,
    scopes: BTreeSet<&str>,
    extra_claims: [(&str, &str); N],
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is valid")
        .as_secs();
    let mut claims = serde_json::Map::new();
    claims.insert("iss".into(), json!(idp.issuer()));
    claims.insert("aud".into(), json!(audience));
    claims.insert("sub".into(), json!("synthetic-caller"));
    claims.insert(
        "scope".into(),
        json!(scopes.into_iter().collect::<Vec<_>>().join(" ")),
    );
    claims.insert("iat".into(), json!(now));
    claims.insert("nbf".into(), json!(now));
    claims.insert("exp".into(), json!(now + 900));
    claims.insert("jti".into(), json!(format!("fixture-{fixture}-{now}")));
    for (name, value) in extra_claims {
        claims.insert(name.into(), json!(value));
    }
    sign_ed25519_compact_jwt(
        fixtures::ED25519_PRIVATE_JWK,
        "at+jwt",
        "registry-platform-testing-ed25519-1",
        Value::Object(claims),
    )
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Value>,
    trace_id: &str,
) -> (StatusCode, Value) {
    let bytes = body
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .expect("request body serializes")
        .unwrap_or_default();
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("traceparent", format!("00-{trace_id}-0000000000000001-01"))
        .body(Body::from(bytes))
        .expect("request builds");
    if body.is_some() {
        request.headers_mut().insert(
            CONTENT_TYPE,
            "application/json".parse().expect("content type header"),
        );
    }
    if let Some(token) = bearer {
        request.headers_mut().insert(
            AUTHORIZATION,
            format!("Bearer {token}").parse().expect("bearer header"),
        );
    }
    let response = app.clone().oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response reads");
    let document = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!("response is JSON ({status}): {error}; response body withheld")
    });
    (status, document)
}

async fn send_representation(
    app: &axum::Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    media_type: &str,
    trace_id: &str,
) -> (StatusCode, http::HeaderMap, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(ACCEPT, media_type)
        .header("traceparent", format!("00-{trace_id}-0000000000000001-01"))
        .body(Body::empty())
        .expect("request builds");
    if let Some(token) = bearer {
        request.headers_mut().insert(
            AUTHORIZATION,
            format!("Bearer {token}").parse().expect("bearer header"),
        );
    }
    let response = app.clone().oneshot(request).await.expect("router responds");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response reads");
    let document = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!("response is JSON ({status}): {error}; response body withheld")
    });
    (status, headers, document)
}

async fn send_raw_body(
    app: &axum::Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    body: &[u8],
    trace_id: &str,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("traceparent", format!("00-{trace_id}-0000000000000001-01"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_vec()))
        .expect("request builds");
    if let Some(token) = bearer {
        request.headers_mut().insert(
            AUTHORIZATION,
            format!("Bearer {token}").parse().expect("bearer header"),
        );
    }
    let response = app.clone().oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response reads");
    let document = serde_json::from_slice(&bytes).expect("response is JSON");
    (status, document)
}

fn assert_problem(response: (StatusCode, Value), status: StatusCode, code: &str) {
    assert_eq!(response.0, status, "problem response body withheld");
    assert_eq!(response.1["code"], code);
    let text = response.1.to_string();
    for absent in [
        "PUBLIC-SEMANTIC-CANARY",
        "PROTECTED-SEMANTIC-CANARY",
        "PROTECTED-CANARY",
        "lookup-a1",
        "zone-a",
    ] {
        assert!(!text.contains(absent), "problem disclosed {absent}");
    }
}

fn assert_success(response: (StatusCode, Value)) -> Value {
    assert_eq!(response.0, StatusCode::OK, "response body withheld");
    response.1
}

fn assert_success_with_headers(
    response: (StatusCode, http::HeaderMap, Value),
) -> (StatusCode, http::HeaderMap, Value) {
    assert_eq!(response.0, StatusCode::OK, "response body withheld");
    response
}

fn assert_profile_link(headers: &http::HeaderMap) {
    let link = headers
        .get(LINK)
        .and_then(|value| value.to_str().ok())
        .expect("Registry Record success carries Link");
    assert!(link.contains(&format!("<{REGISTRY_RECORD_PROFILE_ID}>; rel=\"profile\"")));
}

fn assert_matches_semantic_gold(document: &Value, gold: &Value, visibility: &str) {
    let dataset = semantic_dataset(gold, visibility);
    let (dataset_identifier, entity_type_identifier) = relay_resource_identifiers(visibility);
    assert_eq!(gold["profileIdentifier"], REGISTRY_RECORD_PROFILE_ID);
    assert_eq!(document["meta"]["registryIdentifier"], REGISTRY_ID);
    assert_eq!(document["meta"]["datasetIdentifier"], dataset_identifier);
    assert_eq!(
        document["meta"]["entityTypeIdentifier"],
        entity_type_identifier
    );
    assert_eq!(
        document["data"]["revisionIdentifier"],
        dataset["records"][0]["revisionIdentifier"]
    );
    assert_eq!(
        document["data"]["domainData"],
        dataset["records"][0]["domainData"]
    );
    assert!(document["data"]["recordIdentifier"]
        .as_str()
        .is_some_and(|identifier| !identifier.is_empty()));
}

fn assert_collection_matches_semantic_gold(document: &Value, gold: &Value, visibility: &str) {
    let dataset = semantic_dataset(gold, visibility);
    let (dataset_identifier, entity_type_identifier) = relay_resource_identifiers(visibility);
    assert_eq!(gold["profileIdentifier"], REGISTRY_RECORD_PROFILE_ID);
    assert_eq!(document["meta"]["registryIdentifier"], REGISTRY_ID);
    assert_eq!(document["meta"]["datasetIdentifier"], dataset_identifier);
    assert_eq!(
        document["meta"]["entityTypeIdentifier"],
        entity_type_identifier
    );
    let expected = &dataset["records"][0]["domainData"];
    assert!(document["items"]
        .as_array()
        .expect("collection items")
        .iter()
        .any(|item| {
            item["revisionIdentifier"] == dataset["records"][0]["revisionIdentifier"]
                && &item["domainData"] == expected
        }));
    assert!(document["pageInfo"].get("nextCursor").is_some());
}

fn relay_resource_identifiers(visibility: &str) -> (&'static str, &'static str) {
    match visibility {
        "public" => ("public-units", PUBLIC_RESOURCE),
        "protected" => ("protected-units", PROTECTED_RESOURCE),
        _ => panic!("unknown semantic gold visibility {visibility}"),
    }
}

fn assert_concealed_equivalence(insufficient: (StatusCode, Value), unknown: (StatusCode, Value)) {
    assert_eq!(insufficient.0, StatusCode::NOT_FOUND);
    assert_eq!(unknown.0, StatusCode::NOT_FOUND);
    let mut insufficient = insufficient.1;
    let mut unknown = unknown.1;
    insufficient
        .as_object_mut()
        .expect("problem object")
        .remove("traceId");
    unknown
        .as_object_mut()
        .expect("problem object")
        .remove("traceId");
    assert_eq!(insufficient, unknown);
    assert_eq!(insufficient["code"], "resource.not_found");
    let rendered = insufficient.to_string();
    for absent in [
        PROTECTED_RESOURCE,
        "protected-units",
        "PROTECTED-SEMANTIC-CANARY",
    ] {
        assert!(
            !rendered.contains(absent),
            "concealment problem disclosed {absent}"
        );
    }
}

fn exact_generated_response_schema(
    artifacts: &ArtifactSet,
    operation_identifier: &str,
    media_type: &str,
) -> JSONSchema {
    let openapi = artifact_json(artifacts, "openapi.full.yaml");
    let matches = openapi["paths"]
        .as_object()
        .expect("generated OpenAPI paths")
        .values()
        .flat_map(|path| {
            path.as_object()
                .into_iter()
                .flat_map(|methods| methods.values())
        })
        .filter(|operation| operation["operationId"] == operation_identifier)
        .map(|operation| operation["responses"]["200"]["content"][media_type]["schema"].clone())
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1);
    assert_eq!(
        openapi["paths"]
            .as_object()
            .expect("generated OpenAPI paths")
            .values()
            .flat_map(|path| path
                .as_object()
                .into_iter()
                .flat_map(|methods| methods.values()))
            .find(|operation| operation["operationId"] == operation_identifier)
            .expect("operation exists")["x-registry-responseProfile"],
        REGISTRY_RECORD_PROFILE_ID
    );
    let mut options = JSONSchema::options();
    options
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true);
    for artifact in artifacts
        .artifacts
        .iter()
        .filter(|artifact| artifact.media_type == "application/schema+json")
    {
        let schema: Value =
            serde_json::from_slice(&artifact.content).expect("generated schema parses");
        if let Some(identifier) = schema.get("$id").and_then(Value::as_str) {
            options.with_document(identifier.to_owned(), schema);
        }
    }
    options
        .compile(&matches.into_iter().next().expect("one response schema"))
        .expect("exact generated response schema compiles locally")
}

fn assert_meta_constant_mutations_are_rejected(validator: &JSONSchema, document: &Value) {
    for member in [
        "registryIdentifier",
        "datasetIdentifier",
        "entityTypeIdentifier",
    ] {
        let mut mutated = document.clone();
        mutated["meta"][member] = json!(format!("wrong-{member}"));
        assert!(
            !validator.is_valid(&mutated),
            "exact generated schema accepted changed meta.{member}"
        );
    }
}

fn shared_base_validator() -> JSONSchema {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../products/registry-record/schema/registry-record-v1.schema.json"
    ))
    .expect("shared Registry Record schema is JSON");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .expect("shared Registry Record schema compiles locally")
}

fn semantic_gold() -> Value {
    serde_json::from_str(include_str!(
        "../../../products/registry-record/fixtures/cross-product/semantic-gold.json"
    ))
    .expect("cross-product semantic gold is strict JSON")
}

fn semantic_dataset<'a>(gold: &'a Value, visibility: &str) -> &'a Value {
    gold["datasets"]
        .as_array()
        .expect("gold datasets")
        .iter()
        .find(|dataset| dataset["visibility"] == visibility)
        .unwrap_or_else(|| panic!("gold has a {visibility} dataset"))
}

fn assert_record_state(
    document: &Value,
    operation: &str,
    disclosure: &str,
    field: &str,
    expected_value: &str,
) {
    let (dataset_identifier, entity_type_identifier) = if operation.starts_with("public-unit.") {
        ("public-units", "public-unit")
    } else {
        ("protected-units", "protected-unit")
    };
    assert_eq!(document["meta"]["registryIdentifier"], REGISTRY_ID);
    assert_eq!(document["meta"]["datasetIdentifier"], dataset_identifier);
    assert_eq!(
        document["meta"]["entityTypeIdentifier"],
        entity_type_identifier
    );
    assert!(document["data"].get("registryIdentifier").is_none());
    assert!(document["data"].get("datasetIdentifier").is_none());
    assert!(document["data"].get("entityTypeIdentifier").is_none());
    assert_eq!(
        document["data"]["recordIdentifier"],
        if operation.starts_with("public-unit.") {
            PUBLIC_RECORD_ID
        } else {
            PROTECTED_RECORD_ID
        }
    );
    assert_eq!(document["meta"]["operationIdentifier"], operation);
    assert_eq!(document["meta"]["disclosureProfile"], disclosure);
    assert_eq!(document["meta"]["selectedFields"], json!([field]));
    assert_eq!(
        document["data"]["domainData"],
        json!({field: expected_value})
    );
    assert!(document["data"]["schemaReference"]
        .as_str()
        .is_some_and(|reference| reference.contains(
            operation
                .split('.')
                .next()
                .expect("operation identifier has a resource segment")
        )));
}

fn assert_audit_boundary(
    records: &[Value],
    trace_id: &str,
    resource: &str,
    operation: &str,
    disclosure: &str,
    row_boundary: &str,
    field: &str,
) {
    let matching = records
        .iter()
        .filter(|record| record["traceId"] == trace_id)
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        2,
        "attempt and terminal audit for {trace_id}"
    );
    assert_eq!(matching[0]["phase"], "attempt");
    assert_eq!(matching[1]["phase"], "terminal");
    assert_eq!(matching[1]["outcome"], "released");
    for record in matching {
        assert_eq!(record["registryIdentifier"], REGISTRY_ID);
        assert_eq!(record["resourceIdentifier"], resource);
        assert_eq!(record["operationIdentifier"], operation);
        assert_eq!(record["disclosureProfile"], disclosure);
        assert_eq!(record["rowBoundaryKind"], row_boundary);
        assert_eq!(
            record["processingDescriptionIdentifiers"],
            if operation.starts_with("protected-unit.") {
                json!(["protected-consultation"])
            } else {
                json!([])
            }
        );
        assert_eq!(record["selectedProperties"], json!([field]));
        assert_eq!(record["sourceRevision"]["profile"], "snapshot");
    }
}
