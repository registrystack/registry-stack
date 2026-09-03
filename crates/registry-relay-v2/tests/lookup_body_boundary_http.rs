// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use http::{Request, StatusCode};
use registry_platform_audit::{AuditChainHasher, AuditEnvelope, AuditError, AuditSink, ChainState};
use registry_platform_sqlite::{
    inspect_schema, materialize_fixture, CapturedSnapshot, DatabaseProfile, InspectionLimits,
    SchemaObjectKind,
};
use registry_relay_v2::artifacts::generate_artifacts;
use registry_relay_v2::audit::RelayAudit;
use registry_relay_v2::compiler::{
    classification_inventory_digest, compile_contract, compile_contract_with_governed_files,
    GovernedFileSet,
};
use registry_relay_v2::contract::RegistryContract;
use registry_relay_v2::model::{
    CompileProfile, ObservedColumn, ObservedSourceSchema, ObservedView, OperationKind,
};
use registry_relay_v2::server::{router, InstitutionMetadata, RelayService, ServiceMetadata};
use registry_relay_v2::sqlite_runtime::{RuntimeSourceBinding, SqliteRuntime, SqliteRuntimeLimits};
use serde_json::{json, Value};
use tower::ServiceExt as _;

const SOURCE: &str = "source";
const RESOURCE: &str = "record";
const REGISTRATION_NUMBER: &str = "ABCDEFGHIJKL";
const CONTROLLED_CODE: &str = "é\"";
const PUBLIC_LABEL: &str = "RELEASE-CANARY";
const RECORD_ID: &str = "record-canary";
const TRACE_ID: &str = "00000000000000000000000000000070";

const FIXTURE_SQL: &str = r#"
CREATE TABLE source_records (
    record_id TEXT PRIMARY KEY NOT NULL,
    revision TEXT NOT NULL,
    lifecycle TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    registration_number TEXT NOT NULL,
    event_type TEXT NOT NULL,
    public_label TEXT NOT NULL
) STRICT;

INSERT INTO source_records VALUES
('record-canary', '1', 'ACTIVE', '2026-08-10T00:00:00Z', 'ABCDEFGHIJKL', 'é"', 'RELEASE-CANARY');

CREATE VIEW relay_records AS
SELECT record_id, revision, lifecycle, recorded_at, registration_number, event_type, public_label
FROM source_records;
"#;

const CONTRACT_YAML: &str = r#"
apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata: {id: lookup-boundary, version: "1", title: Lookup boundary}
registry:
  registryIdentifier: urn:example:registry:lookup-boundary
  name: Lookup boundary Registry
  authority: {identifier: urn:example:authority, name: Registry Authority}
  authoritativeScope: Synthetic exact lookup boundary
  baseUri: https://registry.example.invalid/lookup-boundary/
  identifierLifecyclePolicyRef: governance/identifier-lifecycle.yaml
  alignmentTargets:
    - {name: synthetic-registry-profile, version: "1", status: directional}
governance: {controller: urn:example:authority, publisher: urn:example:authority, auditOwner: urn:example:audit}
semantics: {localVocabulary: https://registry.example.invalid/vocabulary/}
classifications:
  privacy: {scheme: https://w3id.org/dpv, version: "2.3"}
  institutional: {scheme: urn:example:classification, version: "1"}
  handling: {scheme: https://id.registrystack.org/vocab/handling, version: "1"}
  provenanceRef: governance/classification-review.yaml
sources:
  source: {kind: sqlite, profile: snapshot, expectedSchemaFingerprint: "OBSERVED_FINGERPRINT"}
resources:
  - id: record
    datasetIdentifier: records
    entityTypeIdentifier: record
    title: Record
    description: One governed synthetic Record
    semanticClass: local:Record
    source: {source: source, view: relay_records}
    classificationDefaults: {privacy: non-personal, institutional: public, handling: public, status: reviewed}
    recordContext:
      recordIdentifier: {sourceColumn: record_id}
      revisionIdentifier: {sourceColumn: revision}
      lifecycleState: {sourceColumn: lifecycle, codelist: codelists/lifecycle.yaml}
      recordedAt: {sourceColumn: recorded_at}
    sourceColumnClassifications:
      registration_number: {privacy: non-personal}
      event_type: {privacy: non-personal}
    properties:
      publicLabel:
        label: Public label
        description: Public synthetic label
        sourceColumn: public_label
        type: string
        sourceRequired: true
        semanticTerm: local:publicLabel
    disclosureProfiles: {public: {properties: [publicLabel]}}
    operations:
      lookups:
        - id: by-registration
          requestBody:
            maximumBytes: EXACT_BODY_BOUND
            selectors:
              registrationNumber: {sourceColumn: registration_number, type: string, minimumBytes: 12, maximumBytes: 96}
              eventType: {sourceColumn: event_type, type: controlled-code, codelist: codelists/event-types.yaml}
          defaultAccessProfile: public
          accessProfiles:
            public: {access: public, disclosureProfile: public}
    processingDescriptions:
      - id: public-consultation
        operationRefs: [lookup:by-registration]
        purpose: public-consultation
        recipientClass: public
        legalBasisRef: governance/legal-basis.yaml
        dpvProfileRef: governance/processing.dpv.yaml
        safeguards: [property-minimization]
metadataVisibility: {service: public, resources: public, semantics: public, classifications: public, processing: public}
"#;

#[derive(Default)]
struct RecordingSink {
    records: Mutex<Vec<AuditEnvelope>>,
}

impl RecordingSink {
    fn values(&self) -> Vec<Value> {
        self.records
            .lock()
            .expect("audit lock")
            .iter()
            .map(|envelope| envelope.record.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl AuditSink for RecordingSink {
    async fn write(&self, envelope: &AuditEnvelope) -> Result<(), AuditError> {
        self.records
            .lock()
            .expect("audit lock")
            .push(envelope.clone());
        Ok(())
    }

    #[allow(deprecated)]
    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(self
            .records
            .lock()
            .expect("audit lock")
            .last()
            .map(|envelope| envelope.record_hash))
    }

    async fn tail_hash_with_hasher(
        &self,
        _hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        Ok(self
            .records
            .lock()
            .expect("audit lock")
            .last()
            .map(|envelope| envelope.record_hash))
    }
}

#[tokio::test]
async fn governed_controlled_code_succeeds_at_the_exact_compiled_body_boundary() {
    let request_body = serde_json::to_vec(&json!({
        "selectors": {
            "registrationNumber": REGISTRATION_NUMBER,
            "eventType": CONTROLLED_CODE,
        }
    }))
    .expect("compact request body serializes");
    let exact_body_bound = u32::try_from(request_body.len()).expect("request body length fits");
    assert_eq!(serde_json::to_vec(CONTROLLED_CODE).unwrap().len(), 6);
    assert_eq!(exact_body_bound, 70);

    let temp = tempfile::tempdir().expect("temporary fixture creates");
    let database = temp.path().join("fixture.sqlite");
    materialize_fixture(&database, FIXTURE_SQL).expect("fixture materializes");
    let captured = CapturedSnapshot::capture(&database).expect("fixture captures");
    let catalog = inspect_schema(
        &DatabaseProfile::Snapshot(captured),
        &InspectionLimits {
            maximum_objects: 100,
            maximum_sql_bytes: 128 * 1024,
            maximum_statement_steps: 100_000,
            timeout: Duration::from_secs(2),
        },
    )
    .expect("fixture schema inspects");
    let contract_yaml = CONTRACT_YAML
        .replace("OBSERVED_FINGERPRINT", &catalog.fingerprint)
        .replace("EXACT_BODY_BOUND", &exact_body_bound.to_string());
    let contract = RegistryContract::parse_yaml(&contract_yaml).expect("contract parses");
    let observed = vec![ObservedSourceSchema {
        source: SOURCE.into(),
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
        .expect("provisional production inventory compiles");
    let inventory_digest =
        classification_inventory_digest(&inventory).expect("classification inventory digests");
    let review = format!(
        "apiVersion: relay.registrystack.org/classification-review/v1\nkind: ClassificationReview\nregistryIdentifier: urn:example:registry:lookup-boundary\nclassificationInventoryDigest: {inventory_digest}\nmethod: manual\nreviewer: urn:example:authority\nreviewDate: 2026-08-10\nstatus: reviewed\nrationaleRef: governance/classification-rationale.md\n"
    );
    let governed = GovernedFileSet::from([
        (
            "governance/identifier-lifecycle.yaml".into(),
            b"status: reviewed\npolicy: identifiers are not reassigned\n".to_vec(),
        ),
        (
            "governance/classification-review.yaml".into(),
            review.into_bytes(),
        ),
        (
            "governance/classification-rationale.md".into(),
            b"Synthetic classification review.\n".to_vec(),
        ),
        (
            "governance/legal-basis.yaml".into(),
            b"status: reviewed\nbasis: public-consultation\n".to_vec(),
        ),
        (
            "governance/processing.dpv.yaml".into(),
            b"status: reviewed\nprofile: https://w3id.org/dpv/2.3\n".to_vec(),
        ),
        (
            "codelists/lifecycle.yaml".into(),
            b"id: lifecycle\nversion: 1\nstatus: reviewed\nvalues: [ACTIVE]\n".to_vec(),
        ),
        (
            "codelists/event-types.yaml".into(),
            format!(
                "id: event-types\nversion: 1\nstatus: reviewed\nvalues: [{}]\n",
                serde_json::to_string(CONTROLLED_CODE).expect("controlled code serializes")
            )
            .into_bytes(),
        ),
    ]);
    let registry = Arc::new(
        compile_contract_with_governed_files(
            &contract,
            &observed,
            CompileProfile::Production,
            &governed,
        )
        .unwrap_or_else(|report| panic!("production contract compiles: {report:?}")),
    );
    let lookup = registry.resources[0]
        .operations
        .iter()
        .find(|operation| matches!(operation.kind, OperationKind::Lookup { .. }))
        .expect("lookup compiles");
    assert_eq!(
        lookup.query.maximum_request_body_bytes,
        Some(exact_body_bound)
    );
    assert_eq!(
        request_body.len(),
        usize::try_from(
            lookup
                .query
                .maximum_request_body_bytes
                .expect("lookup body bound compiles")
        )
        .expect("compiled body bound fits")
    );

    let artifacts = Arc::new(generate_artifacts(&registry).expect("artifacts generate"));
    let sqlite = Arc::new(
        SqliteRuntime::open(
            &registry,
            &BTreeMap::from([(
                SOURCE.to_owned(),
                RuntimeSourceBinding {
                    path: database.clone(),
                },
            )]),
            SqliteRuntimeLimits {
                request_timeout: Duration::from_secs(2),
                concurrent_queries: 1,
            },
        )
        .expect("SQLite runtime opens"),
    );
    let sink = Arc::new(RecordingSink::default());
    let sink_object: Arc<dyn AuditSink> = sink.clone();
    let chain = Arc::new(
        ChainState::bootstrap_unkeyed_dev_only(sink_object.as_ref())
            .await
            .expect("audit chain starts"),
    );
    let service = Arc::new(RelayService::new(
        Arc::clone(&registry),
        artifacts,
        sqlite,
        None,
        RelayAudit::new(chain, sink_object),
        None,
        Duration::from_secs(300),
        Duration::from_secs(2),
        None,
        ServiceMetadata {
            authority: InstitutionMetadata {
                identifier: contract.registry.authority.identifier.clone(),
                name: contract.registry.authority.name.clone(),
            },
            operator: None,
            authoritative_scope: contract.registry.authoritative_scope.clone(),
            alignment_targets: Vec::new(),
        },
    ));
    let response = router(service)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/resources/record/lookups/by-registration")
                .header("content-type", "application/json")
                .header("traceparent", format!("00-{TRACE_ID}-0000000000000001-01"))
                .body(Body::from(request_body))
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response reads");
    let document: Value = serde_json::from_slice(&response_body).expect("response is JSON");
    assert_eq!(
        document["meta"]["operationIdentifier"],
        "record.lookup.by-registration"
    );
    assert_eq!(document["data"]["domainData"]["publicLabel"], PUBLIC_LABEL);
    let response_wire = String::from_utf8(response_body.to_vec()).expect("response is UTF-8");
    assert!(!response_wire.contains(REGISTRATION_NUMBER));
    assert!(!response_wire.contains(CONTROLLED_CODE));

    let audits = sink.values();
    let matching = audits
        .iter()
        .filter(|record| record["traceId"] == TRACE_ID)
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 2, "attempt and terminal audit");
    assert_eq!(matching[0]["phase"], "attempt");
    assert_eq!(matching[1]["phase"], "terminal");
    assert_eq!(matching[1]["outcome"], "released");
    assert!(matching.iter().all(|record| {
        record["resourceIdentifier"] == RESOURCE
            && record["operationIdentifier"] == "record.lookup.by-registration"
            && record["principalKind"] == "anonymous"
    }));
    let audit_wire = serde_json::to_string(&audits).expect("audit serializes");
    for value in [REGISTRATION_NUMBER, "é", RECORD_ID, PUBLIC_LABEL] {
        assert!(
            !audit_wire.contains(value),
            "audit disclosed source or selector value"
        );
    }
}
