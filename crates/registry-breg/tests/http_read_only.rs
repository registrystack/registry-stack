// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{header::CONTENT_TYPE, Method, Request, StatusCode};
use registry_breg::api::{
    router, HeldReadResponse, HttpService, ReadRuntimeIdentity, ReadServiceError, ReadinessProbe,
    RecordReadKind, RecordReadRequest, RecordReadService, RevisionReadRefusal, RevisionReadRequest,
    RevisionReadService, ServiceFuture, SnapshotReadRequest, SnapshotReadService,
    VerifiedClaimValue, VerifiedRequestClaims,
};
use registry_breg::artifacts::REGISTRY_METADATA_ARTIFACT_PATH;
use registry_breg::contract::{ModuleAssetSource, Operation};
use registry_breg::cursor::CursorCodec;
use registry_breg::cursor::{CursorAdapter, CursorRepresentation};
use registry_breg::{
    compile_project, compile_project_with_assets, parse_project_yaml, CompileProfile,
};
use registry_platform_canonical_json::parse_json_strict;
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

#[path = "../src/query.rs"]
mod strict_query;

const PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: read-surface
  version: 0.1.0
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
entities:
  - id: case
    primaryDataset: test-dataset
    route: cases
    mutationMode: mutable
    tombstone: true
    batch: {maximumItems: 10, maximumBytes: 65536}
    classification: public
    fields:
      - {id: label, type: string, required: true, maxLength: 100, classification: public}
      - {id: secret, type: string, required: true, maxLength: 100, classification: restricted}
      - {id: jurisdiction, type: string, required: true, maxLength: 32, classification: internal}
  - id: protected-note
    primaryDataset: test-dataset
    route: notes
    mutationMode: create_only
    classification: restricted
    fields:
      - {id: text, type: text, required: true, maxLength: 200, classification: restricted}
accessProfiles:
  - id: public
    default: true
    anonymous: true
    grants:
      - entity: case
        operations: [get, list]
        readableFields: [label]
        filterableFields: [label]
        sortableFields: [label]
  - id: caseworker
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    requiredPurposes: [case-management]
    grants:
      - entity: case
        operations: [create, get, list, patch, tombstone, batch, revisions]
        allowCount: true
        readableFields: [label, secret, jurisdiction]
        writableFields: [label, secret, jurisdiction]
        filterableFields: [label, jurisdiction]
        sortableFields: [label]
        rowBoundaries:
          - {field: jurisdiction, claim: jurisdictions, operator: in}
      - entity: protected-note
        operations: [create, get, list]
        readableFields: [text]
        writableFields: [text]
"#;

const LOOKUP_PATH_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: lookup-path-surface
  version: 0.1.0
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
entities:
  - id: household
    primaryDataset: test-dataset
    route: households
    mutationMode: mutable
    tombstone: true
    classification: restricted
    fields:
      - {id: household-code, type: string, required: true, maxLength: 64, classification: restricted}
      - {id: administrative-area, type: string, required: true, maxLength: 64, classification: restricted}
      - {id: local-household-number, type: int64, required: true, classification: restricted}
      - {id: private-note, type: string, required: false, maxLength: 64, classification: restricted}
    selectorProfiles:
      - {id: by-household-code, fields: [household-code]}
      - {id: by-local-reference, fields: [administrative-area, local-household-number]}
      - {id: by-private-note, fields: [private-note]}
    readPaths:
      - {id: people, through: membership, to: person, route: people}
  - id: membership
    primaryDataset: test-dataset
    route: memberships
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: household, type: reference, target: household, required: true, classification: restricted}
      - {id: person, type: reference, target: person, required: true, classification: restricted}
  - id: person
    primaryDataset: test-dataset
    route: people
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: person-code, type: string, required: true, maxLength: 64, classification: restricted}
      - {id: sensitive-note, type: string, required: false, maxLength: 64, classification: restricted}
accessProfiles:
  - id: operator
    default: true
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    requiredPurposes: [case-management]
    grants:
      - entity: household
        operations: [get, lookup, list]
        readableFields: [household-code, administrative-area, local-household-number]
        filterableFields: [household-code, administrative-area, local-household-number]
        sortableFields: [household-code]
        lookups:
          - {selector: by-household-code, valueOrigin: request}
          - {selector: by-local-reference, valueOrigin: request}
        readPaths:
          - path: people
            readableFields: [person-code]
            filterableFields: [person-code]
            sortableFields: [person-code]
            allowCount: true
      - entity: person
        operations: [get, list]
        readableFields: [sensitive-note]
        filterableFields: [sensitive-note]
        sortableFields: [sensitive-note]
  - id: viewer
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    requiredPurposes: [case-management]
    grants:
      - entity: household
        operations: [get, lookup]
        readableFields: [household-code]
        rowBoundaries:
          - {field: id, claim: household_id, operator: equals}
        lookups:
          - selector: by-household-code
            valueOrigin: verified_claim
            claimMapping: {household-code: household_code}
"#;

const DERIVED_DISCOVERY_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: derived-discovery
  version: 0.1.0
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
entities:
  - id: benefit-record
    primaryDataset: test-dataset
    route: benefit-records
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: label, type: string, required: true, maxLength: 100, classification: restricted}
    derived:
      - id: eligibility
        sql: sql/eligibility.sql
        key: id
        execution: live
        fields:
          - {id: eligibility-score, type: int64, classification: restricted}
accessProfiles:
  - id: operator
    default: true
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    requiredPurposes: [case-management]
    grants:
      - entity: benefit-record
        operations: [get, list]
        readableFields: [label, eligibility-score]
"#;

const DISCOVERY_MATRIX_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: discovery-matrix
  version: 1
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
entities:
  - id: public-record
    primaryDataset: test-dataset
    route: public-records
    mutationMode: mutable
    classification: public
    fields:
      - {id: label, type: string, required: true, maxLength: 100, classification: public}
      - {id: restricted-canary-field, type: string, maxLength: 100, classification: restricted}
  - id: protected-ledger
    primaryDataset: test-dataset
    route: classified-records
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: classified-status, type: vocabulary-code, vocabulary: classified-status-vocabulary, required: true, classification: restricted}
      - {id: valid-from, type: date, required: true, classification: restricted}
      - {id: valid-to, type: date, classification: restricted}
    temporal:
      startField: valid-from
      endField: valid-to
      scopeFields: [classified-status]
    constraints:
      - {kind: temporal-non-overlap, scopeFields: [classified-status], startField: valid-from, endField: valid-to}
    events:
      - id: classified-created-event
        trigger: created
        projection: [classified-status, valid-from]
        webhook:
          destinationId: classified-operations-destination
accessProfiles:
  - id: public
    default: true
    anonymous: true
    grants:
      - entity: public-record
        operations: [get, list]
        readableFields: [label]
        filterableFields: [label]
        sortableFields: [label]
  - id: caseworker
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    requiredPurposes: [case-management]
    grants:
      - entity: public-record
        operations: [get, list]
        readableFields: [label, restricted-canary-field]
        filterableFields: [label]
        sortableFields: [label]
      - entity: protected-ledger
        operations: [get, list]
        readableFields: [classified-status, valid-from, valid-to]
        filterableFields: [classified-status]
        sortableFields: [valid-from]
vocabularies:
  - id: classified-status-vocabulary
    values: [sealed-canary-value, retired-canary-value]
"#;

const LOGICAL_SCHEMA_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: logical-schema-surface
  version: 1
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
entities:
  - id: logical-record
    primaryDataset: test-dataset
    route: logical-records
    mutationMode: mutable
    classification: public
    fields:
      - {id: household-code, type: string, required: true, maxLength: 64, classification: public}
      - {id: household-kind-code, apiName: householdKind, type: vocabulary-code, vocabulary: household-kind, required: true, classification: public}
      - {id: private-canary-field, apiName: privateCanary, type: string, required: true, maxLength: 64, classification: restricted}
accessProfiles:
  - id: public
    default: true
    anonymous: true
    grants:
      - entity: logical-record
        operations: [get, list]
        readableFields: [household-code, household-kind-code]
vocabularies:
  - id: household-kind
    values: [single, extended]
"#;

const METADATA_LABEL_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: metadata-labels
  version: 1
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
manifestProjection:
  accessProfile: operator
  classificationCeiling: public
  catalog:
    baseUrl: https://metadata-labels.example.test
    title: Metadata Labels
    publisher: {id: metadata-labels-authority, name: Publisher}
  datasets:
    - {id: test-dataset, title: Metadata Labels, owner: Publisher, status: active}
  dataServices:
    - id: metadata-labels-data-service
      title: Metadata Labels
      endpointUrl: https://metadata-labels.example.test
      servesDatasets: [test-dataset]
  publicService: {id: metadata-labels-service, title: Metadata Labels}
  distributions: []
  entities:
    - id: permit
      identifiers:
        - {field: display-token, kind: display}
entities:
  - id: permit
    primaryDataset: test-dataset
    route: permits
    mutationMode: mutable
    classification: public
    fields:
      - {id: import-source, type: string, required: true, maxLength: 64, classification: public}
      - {id: source-record-id, type: string, required: true, maxLength: 64, classification: public}
      - {id: permit-number, type: string, required: true, maxLength: 64, classification: public}
      - {id: display-token, type: string, required: true, maxLength: 64, classification: public}
      - {id: hidden-permit-key, type: string, required: true, maxLength: 64, classification: public}
      - {id: valid-from, type: date, required: true, classification: public}
      - {id: valid-to, type: date, classification: public}
    temporal:
      startField: valid-from
      endField: valid-to
      scopeFields: [permit-number]
    constraints:
      - {kind: unique, fields: [hidden-permit-key]}
      - {kind: unique, fields: [permit-number, valid-from]}
      - {kind: unique, fields: [import-source, source-record-id]}
      - {kind: temporal-non-overlap, scopeFields: [permit-number], startField: valid-from, endField: valid-to}
  - id: inspection
    primaryDataset: test-dataset
    route: inspections
    mutationMode: mutable
    classification: public
    fields:
      - {id: import-source, type: string, required: true, maxLength: 64, classification: public}
      - {id: source-record-id, type: string, required: true, maxLength: 64, classification: public}
      - {id: inspection-code, type: text, required: true, maxLength: 64, classification: public}
      - {id: hidden-inspection-key, type: string, required: true, maxLength: 64, classification: public}
      - {id: valid-from, type: date, required: true, classification: public, validTimeRole: valid_from}
      - {id: valid-to, type: date, classification: public, validTimeRole: valid_to}
    temporal:
      startField: valid-from
      endField: valid-to
      scopeFields: [inspection-code]
    constraints:
      - {kind: unique, fields: [hidden-inspection-key, valid-from]}
      - {kind: unique, fields: [inspection-code, valid-from]}
      - {kind: unique, fields: [import-source, source-record-id]}
      - {kind: temporal-non-overlap, scopeFields: [inspection-code], startField: valid-from, endField: valid-to}
  - id: finding
    primaryDataset: test-dataset
    route: findings
    mutationMode: mutable
    classification: public
    fields:
      - {id: inspection, type: reference, target: inspection, required: true, classification: public}
  - id: certificate
    primaryDataset: test-dataset
    route: certificates
    mutationMode: mutable
    classification: public
    fields:
      - {id: import-source, type: string, required: true, maxLength: 64, classification: public}
      - {id: certificate-code, type: text, required: true, maxLength: 64, classification: public}
      - {id: hidden-certificate-key, type: string, required: true, maxLength: 64, classification: public}
    constraints:
      - {kind: unique, fields: [hidden-certificate-key]}
      - {kind: unique, fields: [certificate-code]}
accessProfiles:
  - id: operator
    default: true
    anonymous: true
    grants:
      - entity: permit
        operations: [get, list]
        readableFields: [import-source, source-record-id, permit-number, display-token, valid-from, valid-to]
      - entity: inspection
        operations: [get, list]
        readableFields: [import-source, source-record-id, inspection-code, valid-from, valid-to]
        filterableFields: [inspection-code]
        sortableFields: [inspection-code]
      - entity: finding
        operations: [get]
        readableFields: [inspection]
      - entity: certificate
        operations: [get, list]
        readableFields: [import-source, certificate-code]
  - id: redacted-reader
    anonymous: true
    grants:
      - entity: inspection
        operations: [get]
        readableFields: [import-source, valid-from]
      - entity: finding
        operations: [get]
        readableFields: [inspection]
"#;

const SPATIAL_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: spatial-read-surface
  version: 0.1.0
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
entities:
  - id: site
    primaryDataset: test-dataset
    route: sites
    mutationMode: mutable
    classification: public
    fields:
      - {id: code, type: string, required: true, maxLength: 64, classification: public}
      - {id: location, type: crs84-point, precision: 6, required: false, classification: public}
    geojson:
      geometryField: location
accessProfiles:
  - id: map-reader
    default: true
    anonymous: true
    grants:
      - entity: site
        operations: [get, list]
        readableFields: [code, location]
        filterableFields: [code]
        spatialQueries:
          bbox:
            maximumLongitudeSpanDegrees: 2
            maximumLatitudeSpanDegrees: 2
  - id: tabular
    anonymous: true
    grants:
      - entity: site
        operations: [get, list]
        readableFields: [code]
"#;

#[derive(Default)]
struct RecordingReadService {
    calls: AtomicUsize,
    refusals: AtomicUsize,
    refusal_fails: AtomicBool,
    requests: Mutex<Vec<RecordReadRequest>>,
}

#[derive(Default)]
struct RecordingRevisionReadService {
    calls: AtomicUsize,
    refusals: AtomicUsize,
    refusal_fails: AtomicBool,
    requests: Mutex<Vec<RevisionReadRequest>>,
}

#[derive(Default)]
struct RecordingSnapshotReadService {
    requests: Mutex<Vec<SnapshotReadRequest>>,
    refusals: AtomicUsize,
    refusal_fails: AtomicBool,
}

impl SnapshotReadService for RecordingSnapshotReadService {
    fn list(
        &self,
        request: SnapshotReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        self.requests.lock().unwrap().push(request);
        Box::pin(async { Ok(held(json!({"items": [], "snapshot": "test-reference"}))) })
    }

    fn refusal(
        &self,
        _: registry_breg::api::RecordReadRefusal,
    ) -> ServiceFuture<'_, Result<(), ReadServiceError>> {
        self.refusals.fetch_add(1, Ordering::SeqCst);
        let fails = self.refusal_fails.load(Ordering::SeqCst);
        Box::pin(async move {
            if fails {
                Err(ReadServiceError::Unavailable)
            } else {
                Ok(())
            }
        })
    }
}

const SNAPSHOT_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry: {id: snapshot-surface, version: 1, defaultLanguage: en, canonicalBaseIri: https://authoring.example.test}
entities:
  - id: assignment
    primaryDataset: test-dataset
    route: assignments
    mutationMode: mutable
    tombstone: true
    classification: restricted
    temporal: {startField: starts, endField: ends}
    fields:
      - {id: label, type: string, required: true, maxLength: 100, classification: restricted}
      - {id: jurisdiction, type: string, required: true, maxLength: 32, classification: restricted}
      - {id: starts, type: date, required: true, classification: restricted}
      - {id: ends, type: date, classification: restricted}
accessProfiles:
  - id: history
    default: true
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    requiredPurposes: [case-management]
    grants:
      - entity: assignment
        operations: [snapshot]
        readableFields: [label, starts, ends]
        filterableFields: [label]
        sortableFields: [label]
        allowCount: true
        rowBoundaries:
          - {field: jurisdiction, claim: jurisdictions, operator: in}
  - id: live-only
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    grants:
      - entity: assignment
        operations: [get, list]
        readableFields: [label, starts, ends]
  - id: revision-only
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    grants:
      - entity: assignment
        operations: [revisions]
        revisionAccess: true
        readableFields: [label]
"#;

fn snapshot_harness(
    source: &str,
    assets: &[ModuleAssetSource],
) -> (
    axum::Router,
    Arc<RecordingReadService>,
    Arc<RecordingSnapshotReadService>,
) {
    let project = parse_project_yaml(source.as_bytes()).unwrap();
    let registry = Arc::new(
        compile_project_with_assets(&project, &[], assets, CompileProfile::Authoring)
            .expect("snapshot project compiles"),
    );
    let records = Arc::new(RecordingReadService::default());
    let snapshots = Arc::new(RecordingSnapshotReadService::default());
    let service = HttpService::new(
        registry,
        read_identity(),
        records.clone(),
        Arc::new(ControlledReadiness(AtomicBool::new(true))),
        cursor_codec(),
    )
    .with_snapshots(snapshots.clone());
    (router(Arc::new(service)), records, snapshots)
}

#[tokio::test]
async fn snapshot_route_requires_its_own_current_authority_and_never_calls_live_reads() {
    let (app, records, snapshots) = snapshot_harness(SNAPSHOT_PROJECT, &[]);
    let metadata = body_json(
        send_to(
            &app,
            Method::GET,
            "/v1/registry?accessProfile=history",
            Some(caseworker_claims("case-management")),
        )
        .await,
    )
    .await;
    let operation = metadata_operation(&metadata, "records.assignment.snapshot");
    assert_eq!(operation["query"]["temporal"]["mode"], "snapshot");
    assert_eq!(
        operation["query"]["temporal"]["snapshot"],
        json!({
            "parameter": "snapshot",
            "required": false,
            "schema": {"type": "string", "maxLength": registry_breg::query::MAX_OPAQUE_VALUE_BYTES},
        })
    );
    assert_eq!(
        operation["query"]["temporal"]["validAt"],
        json!({
            "parameter": "validAt",
            "required": false,
            "schema": {"type": "string", "format": "date"},
        })
    );
    assert_eq!(
        operation["request"]["queryParameters"],
        json!([
            "$count",
            "$filter",
            "$orderby",
            "$select",
            "$skiptoken",
            "$top",
            "snapshot",
            "validAt"
        ])
    );
    for (suffix, claims) in [
        ("", None),
        ("", Some(caseworker_claims("wrong-purpose"))),
        (
            "?accessProfile=live-only",
            Some(caseworker_claims("case-management")),
        ),
        (
            "?accessProfile=revision-only",
            Some(caseworker_claims("case-management")),
        ),
        ("?snapshot=private-canary", None),
    ] {
        let response = send_to(
            &app,
            Method::GET,
            &format!("/v1/records/assignments:snapshot{suffix}"),
            claims,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!String::from_utf8(body_bytes(response).await)
            .unwrap()
            .contains("canary"));
    }
    assert!(snapshots.requests.lock().unwrap().is_empty());
    let response = send_to(&app, Method::GET,
        "/v1/records/assignments:snapshot?validAt=2026-06-05&$select=label&$filter=label%20eq%20'A'&$top=3&$count=true",
        Some(caseworker_claims("case-management"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    {
        let requests = snapshots.requests.lock().unwrap();
        let request = requests.last().unwrap();
        assert_eq!(
            request.plan.kind,
            registry_breg::model::CompiledQueryKind::Snapshot
        );
        assert_eq!(request.plan.temporal_instant.as_deref(), Some("2026-06-05"));
        assert_eq!(
            request.selected_fields,
            BTreeSet::from(["label".to_owned()])
        );
        assert_eq!(request.maximum_records, 4);
        assert!(request.plan.include_count);
        assert_eq!(request.context.row_boundaries().len(), 1);
    }
    assert_eq!(records.calls.load(Ordering::SeqCst), 0);
    assert_eq!(records.refusals.load(Ordering::SeqCst), 0);
    snapshots.refusal_fails.store(true, Ordering::SeqCst);
    let response = send_to(
        &app,
        Method::GET,
        "/v1/records/assignments:snapshot",
        Some(caseworker_claims("wrong-purpose")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    // A caller that presents no credential names no principal, so its refusal
    // is counted rather than journaled and never reaches the refusal audit.
    let before = snapshots.refusals.load(Ordering::SeqCst);
    let response = send_to(&app, Method::GET, "/v1/records/assignments:snapshot", None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(snapshots.refusals.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn discovery_conceals_the_registry_from_callers_without_a_visible_surface() {
    // A project with an anonymous profile keeps its anonymous discovery surface.
    let anonymous = Harness::new(true);
    for uri in ["/openapi.json", "/v1/registry"] {
        let response = anonymous.send(Method::GET, uri, None).await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert!(
            body_json(response)
                .await
                .to_string()
                .contains("read-surface"),
            "{uri}"
        );
    }

    // A project without one refuses discovery exactly as it refuses a record route.
    let (app, records, snapshots) = snapshot_harness(SNAPSHOT_PROJECT, &[]);
    let record_route = send_to(&app, Method::GET, "/v1/records/assignments:snapshot", None).await;
    assert_eq!(record_route.status(), StatusCode::NOT_FOUND);
    let expected = problem_shape(record_route).await;
    for uri in ["/openapi.json", "/v1/registry", "/v1/schemas/assignment"] {
        let response = send_to(&app, Method::GET, uri, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(problem_shape(response).await, expected, "{uri}");
    }

    // A caller with a visible surface still receives both discovery documents.
    let claims = Some(caseworker_claims("case-management"));
    let metadata = send_to(
        &app,
        Method::GET,
        "/v1/registry?accessProfile=history",
        claims.clone(),
    )
    .await;
    assert_eq!(metadata.status(), StatusCode::OK);
    assert_eq!(body_json(metadata).await["id"], "snapshot-surface");
    let openapi = send_to(
        &app,
        Method::GET,
        "/openapi.json?accessProfile=history",
        claims,
    )
    .await;
    assert_eq!(openapi.status(), StatusCode::OK);
    assert_eq!(
        body_json(openapi).await["info"]["title"],
        "snapshot-surface"
    );
    assert_eq!(records.calls.load(Ordering::SeqCst), 0);
    assert!(snapshots.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn snapshot_validity_is_typed_optional_and_has_no_clock_default() {
    for (source, accepted, rejected) in [
        (
            SNAPSHOT_PROJECT.to_owned(),
            "2026-06-05",
            "2026-06-05T00:00:00Z",
        ),
        (
            SNAPSHOT_PROJECT.replace("type: date", "type: timestamp"),
            "2026-06-05T00:00:00Z",
            "2026-06-05",
        ),
    ] {
        let (app, _, snapshots) = snapshot_harness(&source, &[]);
        for value in [Some(accepted), None] {
            let uri = value.map_or_else(
                || "/v1/records/assignments:snapshot".to_owned(),
                |value| format!("/v1/records/assignments:snapshot?validAt={value}"),
            );
            let response = send_to(
                &app,
                Method::GET,
                &uri,
                Some(caseworker_claims("case-management")),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                snapshots
                    .requests
                    .lock()
                    .unwrap()
                    .last()
                    .unwrap()
                    .plan
                    .temporal_instant
                    .as_deref(),
                value
            );
        }
        for invalid in [rejected, "2026-02-30", "2026-06-05T00:00:00%2B07:00"] {
            let response = send_to(
                &app,
                Method::GET,
                &format!("/v1/records/assignments:snapshot?validAt={invalid}"),
                Some(caseworker_claims("case-management")),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        assert_eq!(snapshots.requests.lock().unwrap().len(), 2);
    }
    let non_temporal =
        SNAPSHOT_PROJECT.replace("    temporal: {startField: starts, endField: ends}\n", "");
    let (app, _, snapshots) = snapshot_harness(&non_temporal, &[]);
    let response = send_to(
        &app,
        Method::GET,
        "/v1/records/assignments:snapshot?validAt=2026-06-05",
        Some(caseworker_claims("case-management")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(snapshots.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn snapshot_rejects_ambiguous_time_and_cursor_overrides_before_history_io() {
    let (app, records, snapshots) = snapshot_harness(SNAPSHOT_PROJECT, &[]);
    for query in [
        "recordedAsOf=2026-06-05",
        "asOf=2026-06-05",
        "snapshot=forged-canary",
        "snapshot=a&snapshot=b",
        "validAt=2026-06-05&validAt=2026-07-05",
        "$skiptoken=canary&validAt=2026-06-05",
        "$skiptoken=canary&snapshot=canary",
        "$expand=household",
        "$select=hidden",
        "$top=101",
    ] {
        let response = send_to(
            &app,
            Method::GET,
            &format!("/v1/records/assignments:snapshot?{query}"),
            Some(caseworker_claims("case-management")),
        )
        .await;
        assert!(response.status().is_client_error(), "{query}");
        assert!(!String::from_utf8(body_bytes(response).await)
            .unwrap()
            .contains("canary"));
    }
    assert!(snapshots.requests.lock().unwrap().is_empty());
    assert_eq!(records.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn snapshot_default_projection_excludes_live_derived_fields() {
    let source = DERIVED_DISCOVERY_PROJECT.replace(
        "operations: [get, list]",
        "operations: [get, list, snapshot]",
    );
    let (app, records, snapshots) = snapshot_harness(&source, &[ModuleAssetSource {
        module: None,
        path: "sql/eligibility.sql".to_owned(),
        bytes: b"SELECT benefit.id AS id, 0::bigint AS eligibility_score FROM registry_source.benefit_record benefit".to_vec(),
    }]);
    let metadata = send_to(
        &app,
        Method::GET,
        "/v1/registry",
        Some(caseworker_claims("case-management")),
    )
    .await;
    assert_eq!(metadata.status(), StatusCode::OK);
    let metadata = body_json(metadata).await;
    assert!(metadata["entities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|entity| entity["operations"].as_array().unwrap())
        .any(|operation| operation["operation"] == "snapshot"));
    let response = send_to(
        &app,
        Method::GET,
        "/v1/records/benefit-records:snapshot",
        Some(caseworker_claims("case-management")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        snapshots.requests.lock().unwrap()[0].selected_fields,
        BTreeSet::from(["label".to_owned()])
    );
    for query in [
        "$select=eligibilityScore",
        "$filter=eligibilityScore%20eq%200",
        "$orderby=eligibilityScore",
    ] {
        let response = send_to(
            &app,
            Method::GET,
            &format!("/v1/records/benefit-records:snapshot?{query}"),
            Some(caseworker_claims("case-management")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(snapshots.requests.lock().unwrap().len(), 1);
    assert_eq!(records.calls.load(Ordering::SeqCst), 0);
}

impl RevisionReadService for RecordingRevisionReadService {
    fn detail(
        &self,
        request: RevisionReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().expect("request lock").push(request);
        Box::pin(async {
            Ok(Some(held(json!({
                "id": "00000000-0000-4000-8000-000000000001",
                "revision": 1,
                "data": {"label": "Visible label"}
            }))))
        })
    }

    fn list(
        &self,
        request: RevisionReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().expect("request lock").push(request);
        Box::pin(async { Ok(Some(held(json!({"items": []})))) })
    }

    fn refusal(
        &self,
        _request: RevisionReadRefusal,
    ) -> ServiceFuture<'_, Result<(), ReadServiceError>> {
        self.refusals.fetch_add(1, Ordering::SeqCst);
        let fail = self.refusal_fails.load(Ordering::SeqCst);
        Box::pin(async move {
            if fail {
                Err(ReadServiceError::Unavailable)
            } else {
                Ok(())
            }
        })
    }
}

#[tokio::test]
async fn closed_query_grammar_reaches_record_service_as_compiled_query() {
    let harness = Harness::new(true);
    let accepted = harness
        .send(
            Method::GET,
            "/v1/records/cases?$select=label&$filter=startswith(label,'Visible')&$orderby=label&$top=25",
            None,
        )
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(accepted.headers()["cache-control"], "no-store");
    let request = harness.records.last_request();
    let query = request_query(&request);
    assert_eq!(query.route_id, "records.case.list");
    assert_eq!(query.query_operation_id, "records.case.public.list");
    assert_eq!(query.page_size, 25);
    assert_eq!(request.maximum_records, 26);
    assert_eq!(
        query.order.as_ref().map(|order| order.field_id.as_str()),
        Some("label")
    );
    let predicate = single_filter_predicate(query);
    assert_eq!(predicate.field_id, "label");
    assert_eq!(
        predicate.operator,
        registry_breg::api::ReadFilterOperator::StartsWith
    );

    let before = harness.records.calls();
    let bad_operator = harness
        .send(
            Method::GET,
            "/v1/records/cases?$filter=label%20approximately%20'a'",
            None,
        )
        .await;
    assert_eq!(bad_operator.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(bad_operator).await["code"], "query.invalid");
    assert_eq!(harness.records.calls(), before);
}

#[tokio::test]
async fn bbox_reaches_record_service_only_with_declared_spatial_grant() {
    let harness = Harness::from_project(SPATIAL_PROJECT, true);
    let accepted = harness
        .send_with_accept(
            Method::GET,
            "/v1/records/sites?bbox=100,10,101,11&$filter=code%20eq%20'SITE-A'&$top=25",
            None,
            Some("application/geo+json"),
        )
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(accepted.headers()["content-type"], "application/geo+json");
    assert_eq!(accepted.headers()["cache-control"], "no-store");
    assert_eq!(accepted.headers()["vary"], "authorization, accept");
    assert!(
        accepted.headers().get("link").is_none(),
        "GeoJSON is outside the Registry Record profile"
    );
    let body = body_json(accepted).await;
    assert_eq!(body["numberReturned"], 1);
    assert_eq!(body["features"][0]["geometry"]["type"], "Point");
    let request = harness.records.last_request();
    assert_eq!(request.representation, CursorRepresentation::GeoJson);
    assert_eq!(request.adapter, CursorAdapter::Native);
    let query = request_query(&request);
    assert_eq!(query.query_operation_id, "records.site.map-reader.list");
    let spatial = query.spatial.as_ref().expect("bbox plan is present");
    assert_eq!(spatial.bbox.geometry_field, "location");
    assert_eq!(spatial.bbox.west, "100");
    assert_eq!(spatial.bbox.south, "10");
    assert_eq!(spatial.bbox.east, "101");
    assert_eq!(spatial.bbox.north, "11");
    assert!(query.filter.is_some(), "scalar filter composes with bbox");

    for media_type in ["application/json", "application/ld+json"] {
        let registry_record = harness
            .send_with_accept(
                Method::GET,
                "/v1/records/sites?$select=code,location",
                None,
                Some(media_type),
            )
            .await;
        assert_eq!(registry_record.status(), StatusCode::OK, "{media_type}");
        assert_eq!(
            registry_record.headers()["content-type"],
            media_type,
            "{media_type}"
        );
        assert_eq!(
            registry_record.headers()["link"],
            "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/site>; rel=\"describedby\"",
            "{media_type}"
        );
    }
    let openapi = body_json(harness.send(Method::GET, "/openapi.json", None).await).await;
    let spatial_success = &openapi["paths"]["/v1/records/sites"]["get"]["responses"]["200"];
    assert!(spatial_success["content"]
        .get("application/geo+json")
        .is_some());
    assert_eq!(
        spatial_success["headers"]["Link"]["description"],
        "Emitted only for application/json and application/ld+json Registry Record responses and omitted for application/geo+json. Carries the Registry Record profile and caller-visible entity schema. The describedby target is a relative BReg route and is never derived from Host or forwarded headers."
    );
    assert_eq!(
        spatial_success["headers"]["Link"]["schema"]["const"],
        "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/site>; rel=\"describedby\""
    );

    let before = harness.records.calls();
    let undeclared = harness
        .send(
            Method::GET,
            "/v1/records/sites?accessProfile=tabular&bbox=100,10,101,11",
            None,
        )
        .await;
    assert_eq!(undeclared.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(undeclared).await["code"], "query.invalid");
    assert_eq!(harness.records.calls(), before);

    let malformed = harness
        .send(Method::GET, "/v1/records/sites?bbox=100,10,99,11", None)
        .await;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(malformed).await["code"], "query.invalid");
    assert_eq!(harness.records.calls(), before);
}

#[tokio::test]
async fn geojson_requires_readable_primary_point_but_select_can_omit_geometry() {
    let harness = Harness::from_project(SPATIAL_PROJECT, true);
    let without_geometry = harness
        .send_with_accept(
            Method::GET,
            "/v1/records/sites?$select=code",
            None,
            Some("application/geo+json"),
        )
        .await;
    assert_eq!(without_geometry.status(), StatusCode::OK);
    let body = body_json(without_geometry).await;
    assert_eq!(body["features"][0]["geometry"], Value::Null);
    assert_eq!(body["features"][0]["properties"], json!({"code": "SITE-A"}));
    let request = harness.records.last_request();
    assert_eq!(request.selected_fields, BTreeSet::from(["code".to_owned()]));

    let before = harness.records.calls();
    let unreadable_geometry = harness
        .send_with_accept(
            Method::GET,
            "/v1/records/sites?accessProfile=tabular",
            None,
            Some("application/geo+json"),
        )
        .await;
    assert_eq!(unreadable_geometry.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(unreadable_geometry).await["code"],
        "resource.not_found"
    );
    assert_eq!(harness.records.calls(), before);
}

#[tokio::test]
async fn geojson_accept_negotiation_honors_quality_and_json_preference() {
    let harness = Harness::from_project(SPATIAL_PROJECT, true);
    let geojson_disabled = harness
        .send_with_accept(
            Method::GET,
            "/v1/records/sites",
            None,
            Some("application/geo+json;q=0, application/json;q=0.5"),
        )
        .await;
    assert_eq!(geojson_disabled.status(), StatusCode::OK);
    assert_eq!(
        geojson_disabled.headers()["content-type"],
        "application/json"
    );
    assert_eq!(
        harness.records.last_request().representation,
        CursorRepresentation::Json
    );

    let json_preferred = harness
        .send_with_accept(
            Method::GET,
            "/v1/records/sites",
            None,
            Some("application/geo+json;q=0.8, application/json;q=0.9"),
        )
        .await;
    assert_eq!(json_preferred.status(), StatusCode::OK);
    assert_eq!(json_preferred.headers()["content-type"], "application/json");
    assert_eq!(
        harness.records.last_request().representation,
        CursorRepresentation::Json
    );

    let geojson_preferred = harness
        .send_with_accept(
            Method::GET,
            "/v1/records/sites",
            None,
            Some("application/json;q=0.1, */*;q=0.2, application/geo+json;q=0.9"),
        )
        .await;
    assert_eq!(geojson_preferred.status(), StatusCode::OK);
    assert_eq!(
        geojson_preferred.headers()["content-type"],
        "application/geo+json"
    );
    assert_eq!(
        harness.records.last_request().representation,
        CursorRepresentation::GeoJson
    );
}

#[tokio::test]
async fn bbox_span_grants_use_decimal_semantics_for_fractional_limits() {
    let project = SPATIAL_PROJECT
        .replace(
            "maximumLongitudeSpanDegrees: 2",
            "maximumLongitudeSpanDegrees: 0.3",
        )
        .replace(
            "maximumLatitudeSpanDegrees: 2",
            "maximumLatitudeSpanDegrees: 0.2",
        );
    let harness = Harness::from_project(&project, true);
    let exact_limit = harness
        .send_with_accept(
            Method::GET,
            "/v1/records/sites?bbox=0,13.65,0.3,13.85",
            None,
            Some("application/geo+json"),
        )
        .await;
    assert_eq!(exact_limit.status(), StatusCode::OK);
    let request = harness.records.last_request();
    let query = request_query(&request);
    let spatial = query.spatial.as_ref().expect("bbox query reaches service");
    assert_eq!(spatial.bbox.east, "0.3");
    assert_eq!(spatial.bbox.maximum_longitude_span_degrees, "0.3");
    assert_eq!(spatial.bbox.maximum_latitude_span_degrees, "0.2");

    let before = harness.records.calls();
    let just_over_rounds_down_as_f64 = harness
        .send(
            Method::GET,
            "/v1/records/sites?bbox=0,13.65,0.30000000000000000000000000000000000001,13.85",
            None,
        )
        .await;
    assert_eq!(
        just_over_rounds_down_as_f64.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        body_json(just_over_rounds_down_as_f64).await["code"],
        "query.invalid"
    );
    assert_eq!(harness.records.calls(), before);

    let just_over = harness
        .send(
            Method::GET,
            "/v1/records/sites?bbox=0,13.65,0.3,13.851",
            None,
        )
        .await;
    assert_eq!(just_over.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(just_over).await["code"], "query.invalid");
    assert_eq!(harness.records.calls(), before);
}

#[test]
fn strict_bbox_decimal_helpers_are_exact_and_bounded() {
    assert_eq!(
        strict_query::canonical_positive_decimal_within("3e-1", "360")
            .expect("grant decimal canonicalizes"),
        "0.3"
    );
    assert!(strict_query::decimal_difference_within("0.4", "0.1", "0.3")
        .expect("span compares exactly"));
    assert!(!strict_query::decimal_difference_within(
        "0.30000000000000000000000000000000000001",
        "0",
        "0.3",
    )
    .expect("just-over span compares exactly"));
    assert_eq!(
        strict_query::parse_read_query([("bbox", "0,0,1e-1000,1")]),
        Err(strict_query::QueryParseError::InvalidValue)
    );
}

#[tokio::test]
async fn in_filter_values_are_one_deterministic_finite_set() {
    let harness = Harness::new(true);
    let accepted = harness
        .send(
            Method::GET,
            "/v1/records/cases?accessProfile=caseworker&$filter=jurisdiction%20in%20('area-b','area-a')",
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let last = harness.records.last_request();
    let query = request_query(&last);
    let predicate = single_filter_predicate(query);
    assert_eq!(predicate.field_id, "jurisdiction");
    assert_eq!(
        predicate.values,
        vec!["area-a".to_owned(), "area-b".to_owned()]
    );

    let mixed = harness
        .send(
            Method::GET,
            "/v1/records/cases?accessProfile=caseworker&$filter=secret%20eq%20'DO-NOT-LEAK'",
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(mixed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(mixed).await["code"], "query.invalid");
}

#[tokio::test]
async fn lookup_body_exactness_origin_types_and_unresolved_equivalence_are_value_free() {
    let harness = Harness::from_project(LOOKUP_PATH_PROJECT, true);
    let operator_claims = Some(caseworker_claims("case-management"));
    let metadata = body_json(
        harness
            .send(
                Method::GET,
                "/v1/registry?accessProfile=operator",
                operator_claims.clone(),
            )
            .await,
    )
    .await;
    let lookup = metadata_operation(&metadata, "records.household.lookup");
    let projection_parameter = lookup["request"]["queryParameters"][0]
        .as_str()
        .expect("lookup permits projection");
    assert_eq!(projection_parameter, "$select");
    let projected_lookup = format!(
        "{}?accessProfile=operator&{projection_parameter}=householdCode",
        lookup["path"].as_str().unwrap()
    );
    let accepted = harness
        .send_json(
            Method::POST,
            &projected_lookup,
            operator_claims.clone(),
            json!({
                "selector": "by-local-reference",
                "values": {
                    "administrativeArea": "area-a",
                    "localHouseholdNumber": 7
                }
            }),
        )
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let request = harness.records.last_request();
    assert_eq!(request.maximum_records, 2);
    assert_eq!(
        request.selected_fields,
        BTreeSet::from(["household-code".to_owned()])
    );
    let RecordReadKind::Lookup { selector } = request.kind else {
        panic!("lookup route must reach the service as a lookup request")
    };
    assert_eq!(selector.selector_id, "by-local-reference");
    assert_eq!(
        selector.query_operation_id,
        "records.household.operator.lookup"
    );
    assert_eq!(
        selector
            .values
            .iter()
            .map(|value| (value.field_id.as_str(), value.value.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("administrative-area", "area-a"),
            ("local-household-number", "7")
        ]
    );

    for body in [
        json!({"selector": "by-local-reference"}),
        json!({"selector": "by-local-reference", "values": {"administrativeArea": "area-a", "localHouseholdNumber": "7"}}),
        json!({"selector": "by-local-reference", "values": {"administrativeArea": "area-a", "localHouseholdNumber": 7, "privateNote": "DO-NOT-LEAK"}}),
        json!({"selector": "by-local-reference", "values": {"administrativeArea": "area-a", "localHouseholdNumber": 7}, "extra": "DO-NOT-LEAK"}),
        json!({"selector": "by-local-reference", "values": {"administrative-area": "area-a", "local-household-number": 7}}),
    ] {
        let before = harness.records.calls();
        let response = harness
            .send_json(
                Method::POST,
                "/v1/records/households:lookup?accessProfile=operator",
                operator_claims.clone(),
                body,
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["code"], "request.invalid");
        assert!(!body.to_string().contains("DO-NOT-LEAK"));
        assert_eq!(harness.records.calls(), before);
    }

    let oversized_body = format!(
        r#"{{"selector":"by-household-code","values":{{"householdCode":"{}"}}}}"#,
        "x".repeat(17 * 1024)
    );
    let before = harness.records.calls();
    let oversized = harness
        .send_body(
            Method::POST,
            "/v1/records/households:lookup?accessProfile=operator",
            operator_claims.clone(),
            Some("application/json"),
            Body::from(oversized_body),
        )
        .await;
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(oversized).await["code"], "request.invalid");
    assert_eq!(harness.records.calls(), before);

    let unknown = harness
        .send_json(
            Method::POST,
            "/v1/records/households:lookup?accessProfile=operator",
            operator_claims.clone(),
            json!({"selector": "missing-canary", "values": {"householdCode": "DO-NOT-LEAK"}}),
        )
        .await;
    let unknown_body = problem_shape(unknown).await;
    let ungranted = harness
        .send_json(
            Method::POST,
            "/v1/records/households:lookup?accessProfile=operator",
            operator_claims.clone(),
            json!({"selector": "by-private-note", "values": {"privateNote": "DO-NOT-LEAK"}}),
        )
        .await;
    let ungranted_body = problem_shape(ungranted).await;
    assert_eq!(unknown_body, ungranted_body);
    assert!(!unknown_body.to_string().contains("DO-NOT-LEAK"));
    assert_eq!(unknown_body["code"], "lookup.unresolved");

    let claim_origin_claims = Some(caseworker_claims_with_direct(
        "case-management",
        [
            (
                "household_code",
                VerifiedClaimValue::direct_string("hh-001").expect("claim value"),
            ),
            (
                "household_id",
                VerifiedClaimValue::direct_string("00000000-0000-4000-8000-000000000001")
                    .expect("claim value"),
            ),
        ],
    ));
    let claim_origin = harness
        .send_json(
            Method::POST,
            "/v1/records/households:lookup?accessProfile=viewer",
            claim_origin_claims,
            json!({"selector": "by-household-code"}),
        )
        .await;
    assert_eq!(claim_origin.status(), StatusCode::OK);
    let request = harness.records.last_request();
    let RecordReadKind::Lookup { selector } = request.kind else {
        panic!("claim-origin route must reach the service as a lookup request")
    };
    assert_eq!(selector.selector_id, "by-household-code");
    assert_eq!(
        selector.value_origin,
        registry_breg::contract::LookupValueOrigin::VerifiedClaim
    );
    assert_eq!(selector.values[0].value, "hh-001");

    let claim_values_body = harness
        .send_json(
            Method::POST,
            "/v1/records/households:lookup?accessProfile=viewer",
            Some(caseworker_claims_with_direct(
                "case-management",
                [(
                    "household_id",
                    VerifiedClaimValue::direct_string("00000000-0000-4000-8000-000000000001")
                        .expect("claim value"),
                )],
            )),
            json!({"selector": "by-household-code", "values": {"householdCode": "DO-NOT-LEAK"}}),
        )
        .await;
    assert_eq!(claim_values_body.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(claim_values_body).await["code"],
        "request.invalid"
    );

    let missing_claim = harness
        .send_json(
            Method::POST,
            "/v1/records/households:lookup?accessProfile=viewer",
            Some(caseworker_claims_with_direct(
                "case-management",
                [(
                    "household_id",
                    VerifiedClaimValue::direct_string("00000000-0000-4000-8000-000000000001")
                        .expect("claim value"),
                )],
            )),
            json!({"selector": "by-household-code"}),
        )
        .await;
    assert_eq!(problem_shape(missing_claim).await, unknown_body);
}

#[tokio::test]
async fn relationship_route_uses_path_grant_not_direct_target_rights() {
    let harness = Harness::from_project(LOOKUP_PATH_PROJECT, true);
    let root = "00000000-0000-4000-8000-000000000001";
    let accepted = harness
        .send(
            Method::GET,
            &format!(
                "/v1/records/households/{root}/people?accessProfile=operator&$select=personCode&$filter=startswith(personCode,'P-')&$orderby=personCode&$top=5&$count=true"
            ),
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let request = harness.records.last_request();
    assert_eq!(request.entity_id, "household");
    assert_eq!(request.operation_id, "records.household.path.people");
    assert_eq!(
        request.selected_fields,
        BTreeSet::from(["person-code".to_owned()])
    );
    assert_eq!(request.maximum_records, 6);
    let RecordReadKind::Relationship {
        root_id,
        path_id,
        plan,
    } = request.kind
    else {
        panic!("read-path route must reach the service as a relationship request")
    };
    assert_eq!(root_id, root);
    assert_eq!(path_id, "people");
    assert_eq!(plan.route_id, "records.household.path.people");
    assert_eq!(
        plan.query_operation_id,
        "records.household.operator.path.people"
    );
    assert_eq!(plan.page_size, 5);
    assert!(plan.include_count);
    assert_eq!(
        single_filter_predicate(&plan).field_id,
        "person-code",
        "path filters are target-field filters from the path grant"
    );
    assert_eq!(
        plan.order.as_ref().map(|order| order.field_id.as_str()),
        Some("person-code")
    );

    let before = harness.records.calls();
    let widened = harness
        .send(
            Method::GET,
            &format!(
                "/v1/records/households/{root}/people?accessProfile=operator&$select=sensitiveNote"
            ),
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(widened.status(), StatusCode::BAD_REQUEST);
    let widened_body = body_json(widened).await;
    assert_eq!(widened_body["code"], "query.invalid");
    assert!(!widened_body.to_string().contains("sensitiveNote"));
    assert_eq!(harness.records.calls(), before);

    let unknown_path = harness
        .send(
            Method::GET,
            &format!("/v1/records/households/{root}/unknown-path?accessProfile=viewer"),
            Some(caseworker_claims_with_direct(
                "case-management",
                [(
                    "household_id",
                    VerifiedClaimValue::direct_string(root).expect("claim value"),
                )],
            )),
        )
        .await;
    assert_eq!(unknown_path.status(), StatusCode::NOT_FOUND);
    let unknown_path_body = problem_shape(unknown_path).await;

    let ungranted = harness
        .send(
            Method::GET,
            &format!("/v1/records/households/{root}/people?accessProfile=viewer"),
            Some(caseworker_claims_with_direct(
                "case-management",
                [(
                    "household_id",
                    VerifiedClaimValue::direct_string(root).expect("claim value"),
                )],
            )),
        )
        .await;
    assert_eq!(ungranted.status(), StatusCode::NOT_FOUND);
    assert_eq!(problem_shape(ungranted).await, unknown_path_body);
    assert_eq!(harness.records.calls(), before);
}

#[tokio::test]
async fn relationship_route_conceals_geojson_before_record_service_access() {
    let project = LOOKUP_PATH_PROJECT
        .replace(
            "      - {id: sensitive-note, type: string, required: false, maxLength: 64, classification: restricted}",
            "      - {id: sensitive-note, type: string, required: false, maxLength: 64, classification: restricted}\n      - {id: location, type: crs84-point, precision: 6, required: false, classification: restricted}\n    geojson:\n      geometryField: location",
        )
        .replace(
            "            readableFields: [person-code]",
            "            readableFields: [person-code, location]",
        );
    let harness = Harness::from_project(&project, true);
    let root = "00000000-0000-4000-8000-000000000001";
    let route = format!(
        "/v1/records/households/{root}/people?accessProfile=operator&$select=personCode,location"
    );

    for (media_type, representation) in [
        ("application/json", CursorRepresentation::Json),
        ("application/ld+json", CursorRepresentation::JsonLd),
    ] {
        let response = harness
            .send_with_accept(
                Method::GET,
                &route,
                Some(caseworker_claims("case-management")),
                Some(media_type),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{media_type}");
        assert_eq!(
            response.headers()["content-type"],
            media_type,
            "{media_type}"
        );
        assert_eq!(
            harness.records.last_request().representation,
            representation,
            "{media_type}"
        );
    }

    let calls_before = harness.records.calls();
    let refusals_before = harness.records.refusal_calls();
    let response = harness
        .send_with_accept(
            Method::GET,
            &route,
            Some(caseworker_claims("case-management")),
            Some("application/geo+json"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_json(response).await["code"], "resource.not_found");
    assert_eq!(harness.records.calls(), calls_before);
    assert_eq!(harness.records.refusal_calls(), refusals_before + 1);
    assert_eq!(
        harness.records.last_request().representation,
        CursorRepresentation::JsonLd,
        "the refused GeoJSON representation never reaches the record service"
    );
}

#[tokio::test]
async fn relationship_discovery_uses_target_entity_and_unions_authorized_operation_fields() {
    let project =
        parse_project_yaml(LOOKUP_PATH_PROJECT.as_bytes()).expect("relationship project parses");
    let registry = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("relationship project compiles");
    let path_entry = registry
        .metadata()
        .entities
        .iter()
        .find(|entity| entity.id == "household")
        .and_then(|entity| {
            entity
                .entries
                .iter()
                .find(|entry| entry.route_id == "records.household.path.people")
        })
        .expect("relationship metadata entry is compiled");
    assert_eq!(path_entry.response_entity_id, "person");
    assert_eq!(
        path_entry.readable_fields,
        BTreeSet::from(["person-code".to_owned()])
    );
    let path_filter = registry
        .queries()
        .operations
        .iter()
        .find(|operation| operation.id == "records.household.operator.path.people")
        .and_then(|operation| {
            operation
                .filter_fields
                .iter()
                .find(|field| field.field == "person-code")
        })
        .expect("relationship string filter capability is compiled");
    assert!(path_filter
        .operators
        .contains(&registry_breg::model::CompiledQueryFilterOperator::Contains));

    let harness = Harness::from_project(LOOKUP_PATH_PROJECT, true);
    let claims = Some(caseworker_claims("case-management"));
    let openapi = body_json(
        harness
            .send(
                Method::GET,
                "/openapi.json?accessProfile=operator",
                claims.clone(),
            )
            .await,
    )
    .await;
    assert_eq!(
        openapi["paths"]["/v1/records/households/{record_id}/people"]["get"]
            ["x-registry-responseEntity"],
        "person"
    );
    assert_eq!(
        openapi["components"]["schemas"]["person"]["properties"],
        json!({
            "personCode": {"type": "string", "minLength": 0, "maxLength": 64},
            "sensitiveNote": {"anyOf": [{"type": "string", "minLength": 0, "maxLength": 64}, {"type": "null"}]}
        })
    );

    let person_schema = body_json(
        harness
            .send(
                Method::GET,
                "/v1/schemas/person?accessProfile=operator",
                claims.clone(),
            )
            .await,
    )
    .await;
    assert_eq!(
        person_schema["properties"],
        openapi["components"]["schemas"]["person"]["properties"]
    );
    let household_schema = body_json(
        harness
            .send(
                Method::GET,
                "/v1/schemas/household?accessProfile=operator",
                claims.clone(),
            )
            .await,
    )
    .await;
    assert!(household_schema["properties"]
        .get("householdCode")
        .is_some());
    assert!(household_schema["properties"].get("personCode").is_none());

    let metadata = body_json(
        harness
            .send(Method::GET, "/v1/registry?accessProfile=operator", claims)
            .await,
    )
    .await;
    let person = metadata["entities"]
        .as_array()
        .expect("metadata entities")
        .iter()
        .find(|entity| entity["id"] == "person")
        .expect("target entity is discoverable through direct and relationship reads");
    assert_eq!(
        person["readableFields"],
        json!(["person-code", "sensitive-note"])
    );
}

#[tokio::test]
async fn derived_fields_are_discoverable_as_read_only_response_properties() {
    let project = parse_project_yaml(DERIVED_DISCOVERY_PROJECT.as_bytes())
        .expect("derived discovery project parses");
    let registry = Arc::new(
        compile_project_with_assets(
            &project,
            &[],
            &[ModuleAssetSource {
                module: None,
                path: "sql/eligibility.sql".to_owned(),
                bytes: b"SELECT benefit.id AS id, 0::bigint AS eligibility_score FROM registry_source.benefit_record benefit".to_vec(),
            }],
            CompileProfile::Authoring,
        )
        .expect("derived discovery project compiles"),
    );
    assert!(!registry.entities()["benefit-record"]
        .fields
        .contains_key("eligibility-score"));
    let records = Arc::new(RecordingReadService::default());
    let app = router(Arc::new(HttpService::new(
        registry,
        read_identity(),
        records.clone(),
        Arc::new(ControlledReadiness(AtomicBool::new(true))),
        cursor_codec(),
    )));
    let schema = body_json(
        send_to(
            &app,
            Method::GET,
            "/v1/schemas/benefit-record?accessProfile=operator",
            Some(caseworker_claims("case-management")),
        )
        .await,
    )
    .await;
    assert_eq!(
        schema["properties"]["eligibilityScore"],
        json!({"anyOf": [{"type": "integer", "format": "int64"}, {"type": "null"}], "readOnly": true})
    );
    assert_eq!(
        schema["properties"]["label"],
        json!({"type": "string", "minLength": 0, "maxLength": 100})
    );
    assert_eq!(schema["required"], json!(["label"]));

    let response = send_to(
        &app,
        Method::GET,
        "/v1/records/benefit-records/00000000-0000-4000-8000-000000000001?accessProfile=operator&$select=eligibilityScore",
        Some(caseworker_claims("case-management")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        records.last_request().selected_fields,
        BTreeSet::from(["eligibility-score".to_owned()])
    );
}

#[tokio::test]
async fn continuation_requests_refuse_query_overrides_before_record_io() {
    let harness = Harness::new(true);
    let before = harness.records.calls();
    let response = harness
        .send(
            Method::GET,
            "/v1/records/cases?$skiptoken=opaque-token&$select=label",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "query.invalid");
    assert_eq!(harness.records.calls(), before);
}

#[tokio::test]
async fn known_route_malformed_query_is_refusal_audited_before_response() {
    let harness = Harness::new(true);
    harness.records.refusal_fails.store(true, Ordering::SeqCst);
    let response = harness
        .send(
            Method::GET,
            "/v1/records/cases?$filter=label%20eq",
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(response).await["code"], "source.unavailable");
    assert_eq!(harness.records.calls(), 0);
    assert_eq!(harness.records.refusal_calls(), 1);
}

/// The same refusal from a caller that presents no credential names no
/// principal, so it is never appended to the hash-chained journal: an
/// unauthenticated caller cannot grow the chain or contend for its head lock.
#[tokio::test]
async fn anonymous_malformed_query_is_refused_without_a_refusal_audit() {
    let harness = Harness::new(true);
    harness.records.refusal_fails.store(true, Ordering::SeqCst);
    let response = harness
        .send(Method::GET, "/v1/records/cases?$filter=label%20eq", None)
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["code"], "query.invalid");
    assert_eq!(harness.records.calls(), 0);
    assert_eq!(harness.records.refusal_calls(), 0);
}

#[tokio::test]
async fn legacy_query_keys_are_not_accepted() {
    let harness = Harness::new(true);
    for uri in [
        "/v1/records/cases?fields=label",
        "/v1/records/cases?filter=label:equals:Visible",
        "/v1/records/cases?sort=label",
        "/v1/records/cases?pageSize=25",
        "/v1/records/cases?cursor=opaque-token",
    ] {
        let response = harness.send(Method::GET, uri, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(body_json(response).await["code"], "query.invalid", "{uri}");
    }
    assert_eq!(harness.records.calls(), 0);
}

#[tokio::test]
async fn count_requires_compiled_permission_and_top_is_bounded() {
    let harness = Harness::new(true);
    let public_count = harness
        .send(Method::GET, "/v1/records/cases?$count=true", None)
        .await;
    assert_eq!(public_count.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(public_count).await["code"], "query.invalid");

    let caseworker_count = harness
        .send(
            Method::GET,
            "/v1/records/cases?accessProfile=caseworker&$count=true&$top=1",
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(caseworker_count.status(), StatusCode::OK);
    let body = body_json(caseworker_count).await;
    assert_eq!(body["count"], 1);
    assert_eq!(body["pageInfo"]["nextCursor"], Value::Null);
    let request = harness.records.last_request();
    let query = request_query(&request);
    assert!(query.include_count);
    assert_eq!(query.page_size, 1);
    assert_eq!(request.maximum_records, 2);
}

#[tokio::test]
async fn desc_ordering_and_field_capability_failures_are_value_free() {
    let harness = Harness::new(true);
    for uri in [
        "/v1/records/cases?$orderby=label%20desc",
        "/v1/records/cases?$filter=secret%20eq%20'DO-NOT-LEAK'",
        "/v1/records/cases?$filter=missing%20eq%20'DO-NOT-LEAK'",
    ] {
        let response = harness.send(Method::GET, uri, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let body = body_json(response).await;
        assert_eq!(body["code"], "query.invalid", "{uri}");
        let rendered = body.to_string();
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("missing"));
        assert!(!rendered.contains("DO-NOT-LEAK"));
    }
    assert_eq!(harness.records.calls(), 0);
}

#[tokio::test]
async fn select_refuses_envelope_names_and_filter_grouping_reaches_the_plan() {
    let harness = Harness::new(true);
    // The record envelope carries recordIdentifier and revisionIdentifier, so
    // id and revision are not readable API property names.
    for uri in [
        "/v1/records/cases?$select=id",
        "/v1/records/cases?$select=revision",
        "/v1/records/cases?$select=label,id",
    ] {
        let response = harness.send(Method::GET, uri, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(body_json(response).await["code"], "query.invalid", "{uri}");
    }
    let direct = harness
        .send(
            Method::GET,
            "/v1/records/cases/00000000-0000-4000-8000-000000000001?$select=id",
            None,
        )
        .await;
    assert_eq!(direct.status(), StatusCode::NOT_FOUND);
    assert_eq!(harness.records.calls(), 0);

    let selected_label = harness
        .send(Method::GET, "/v1/records/cases?$select=label", None)
        .await;
    assert_eq!(selected_label.status(), StatusCode::OK);
    assert_eq!(
        harness.records.last_request().selected_fields,
        BTreeSet::from(["label".to_owned()])
    );

    let grouped = harness
        .send(
            Method::GET,
            "/v1/records/cases?accessProfile=caseworker&$filter=(label%20eq%20'Visible'%20or%20jurisdiction%20eq%20'area-a')%20and%20not%20jurisdiction%20eq%20'area-b'",
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(grouped.status(), StatusCode::OK);
    let last = harness.records.last_request();
    let query = request_query(&last);
    assert!(matches!(
        &query.filter,
        Some(registry_breg::api::ReadFilterExpr::Binary {
            op: registry_breg::api::ReadLogicalOp::And,
            ..
        })
    ));
}

#[test]
fn strict_query_debug_output_redacts_identifiers_literals_and_tokens() {
    let query = strict_query::parse_read_query([
        ("accessProfile", "caseworker-canary"),
        ("$filter", "secret eq 'literal-canary'"),
    ])
    .expect("query parses");
    let rendered = format!("{query:?}");
    assert!(!rendered.contains("caseworker-canary"));
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains("literal-canary"));

    let token_query = strict_query::parse_read_query([("$skiptoken", "cursor-canary")])
        .expect("cursor query parses");
    assert!(!format!("{token_query:?}").contains("cursor-canary"));
}

impl RecordingReadService {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn refusal_calls(&self) -> usize {
        self.refusals.load(Ordering::SeqCst)
    }

    fn last_request(&self) -> RecordReadRequest {
        self.requests
            .lock()
            .expect("request lock")
            .last()
            .expect("one request")
            .clone()
    }

    fn record(&self, request: RecordReadRequest) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().expect("request lock").push(request);
    }
}

impl RecordReadService for RecordingReadService {
    fn get(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        let selected_fields = request.selected_fields.clone();
        let representation = request.representation;
        self.record(request);
        Box::pin(async move {
            let record = project_fixture(
                json!({
                    "id": "00000000-0000-4000-8000-000000000001",
                    "revision": 1,
                    "data": {
                            "label": "Visible label",
                            "secret": "DO-NOT-LEAK",
                            "jurisdiction": "area-a",
                            "code": "SITE-A",
                            "location": {"type":"Point","coordinates":[100.5,10.5]}
                    }
                }),
                &selected_fields,
            );
            match representation {
                CursorRepresentation::GeoJson => Ok(Some(geojson_feature(record))),
                CursorRepresentation::Json | CursorRepresentation::JsonLd => {
                    Ok(Some(held_json_representation(record, representation)))
                }
            }
        })
    }

    fn list(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        let selected_fields = request.selected_fields.clone();
        let maximum_records = request.maximum_records;
        let representation = request.representation;
        let include_count = match &request.kind {
            RecordReadKind::List { plan } | RecordReadKind::Relationship { plan, .. } => {
                plan.include_count
            }
            RecordReadKind::Get { .. } | RecordReadKind::Lookup { .. } => false,
        };
        self.record(request);
        Box::pin(async move {
            let mut records = vec![project_fixture(
                json!({
                    "id": "00000000-0000-4000-8000-000000000001",
                    "revision": 1,
                    "data": {
                            "label": "Visible label",
                            "secret": "DO-NOT-LEAK",
                            "jurisdiction": "area-a",
                            "code": "SITE-A",
                            "location": {"type":"Point","coordinates":[100.5,10.5]}
                    }
                }),
                &selected_fields,
            )];
            records.truncate(maximum_records);
            if representation == CursorRepresentation::GeoJson {
                let features = records
                    .into_iter()
                    .map(|record| {
                        let mut properties =
                            record["data"].as_object().cloned().unwrap_or_default();
                        let geometry = properties.remove("location").unwrap_or(Value::Null);
                        json!({
                            "type": "Feature",
                            "id": record["id"],
                            "geometry": geometry,
                            "properties": properties,
                            "registry": {"revision": record["revision"]},
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(HeldReadResponse::from_geojson(&json!({
                    "type": "FeatureCollection",
                    "features": features,
                    "numberReturned": features.len(),
                    "registry": {"pageInfo": {"nextCursor": null}},
                }))
                .expect("fake GeoJSON serializes"))
            } else {
                let mut response = json!({"items": records, "pageInfo": {"nextCursor": null}});
                if include_count {
                    response["count"] = json!(1);
                }
                Ok(held_json_representation(response, representation))
            }
        })
    }

    fn lookup(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        let selected_fields = request.selected_fields.clone();
        self.record(request);
        Box::pin(async move {
            Ok(Some(held(project_fixture(
                json!({
                    "id": "00000000-0000-4000-8000-000000000001",
                    "revision": 1,
                    "data": {
                            "label": "Visible label",
                            "secret": "DO-NOT-LEAK",
                            "jurisdiction": "area-a"
                    }
                }),
                &selected_fields,
            ))))
        })
    }

    fn refusal(
        &self,
        _request: registry_breg::api::RecordReadRefusal,
    ) -> ServiceFuture<'_, Result<(), ReadServiceError>> {
        let fail = self.refusal_fails.load(Ordering::SeqCst);
        self.refusals.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if fail {
                Err(ReadServiceError::Unavailable)
            } else {
                Ok(())
            }
        })
    }
}

struct ControlledReadiness(AtomicBool);

impl ReadinessProbe for ControlledReadiness {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        let ready = self.0.load(Ordering::SeqCst);
        Box::pin(async move { ready })
    }
}

struct Harness {
    app: axum::Router,
    records: Arc<RecordingReadService>,
    readiness: Arc<ControlledReadiness>,
}

impl Harness {
    fn new(ready: bool) -> Self {
        Self::from_project(PROJECT, ready)
    }

    fn from_project(source: &str, ready: bool) -> Self {
        let project = parse_project_yaml(source.as_bytes()).expect("project parses");
        let registry = Arc::new(
            compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles"),
        );
        let records = Arc::new(RecordingReadService::default());
        let readiness = Arc::new(ControlledReadiness(AtomicBool::new(ready)));
        let app = router(Arc::new(HttpService::new(
            registry,
            read_identity(),
            records.clone(),
            readiness.clone(),
            cursor_codec(),
        )));
        Self {
            app,
            records,
            readiness,
        }
    }

    async fn send(
        &self,
        method: Method,
        uri: &str,
        claims: Option<VerifiedRequestClaims>,
    ) -> axum::response::Response {
        self.send_with_accept(method, uri, claims, None).await
    }

    async fn send_with_accept(
        &self,
        method: Method,
        uri: &str,
        claims: Option<VerifiedRequestClaims>,
        accept: Option<&str>,
    ) -> axum::response::Response {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        let mut request = request.body(Body::empty()).expect("request");
        if let Some(claims) = claims {
            request.extensions_mut().insert(claims);
        }
        let mut app = self.app.clone();
        app.call(request).await.expect("response")
    }

    async fn send_json(
        &self,
        method: Method,
        uri: &str,
        claims: Option<VerifiedRequestClaims>,
        body: Value,
    ) -> axum::response::Response {
        self.send_body(
            method,
            uri,
            claims,
            Some("application/json"),
            Body::from(serde_json::to_vec(&body).expect("JSON body serializes")),
        )
        .await
    }

    async fn send_body(
        &self,
        method: Method,
        uri: &str,
        claims: Option<VerifiedRequestClaims>,
        content_type: Option<&str>,
        body: Body,
    ) -> axum::response::Response {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        let mut request = request.body(body).expect("request");
        if let Some(claims) = claims {
            request.extensions_mut().insert(claims);
        }
        let mut app = self.app.clone();
        app.call(request).await.expect("response")
    }
}

fn revision_harness() -> (axum::Router, Arc<RecordingRevisionReadService>) {
    let project = PROJECT.replace(
        "operations: [create, get, list, patch, tombstone, batch, revisions]",
        "operations: [create, get, list, patch, tombstone, batch, revisions]\n        revisionAccess: true",
    );
    let project = parse_project_yaml(project.as_bytes()).expect("revision project parses");
    let registry = Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("revision project compiles"),
    );
    let records = Arc::new(RecordingReadService::default());
    let revisions = Arc::new(RecordingRevisionReadService::default());
    let readiness = Arc::new(ControlledReadiness(AtomicBool::new(true)));
    let service = HttpService::new(
        registry,
        read_identity(),
        records,
        readiness,
        cursor_codec(),
    )
    .with_revisions(revisions.clone());
    (router(Arc::new(service)), revisions)
}

async fn send_to(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("request");
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("response")
}

fn read_identity() -> ReadRuntimeIdentity {
    ReadRuntimeIdentity {
        package_revision: "package-read-test".to_owned(),
        schema_fingerprint: "schema-read-test".to_owned(),
    }
}

fn cursor_codec() -> Arc<CursorCodec> {
    Arc::new(
        CursorCodec::new(
            Zeroizing::new(vec![0x42; 32]),
            std::time::Duration::from_secs(300),
        )
        .expect("test cursor key is valid"),
    )
}

#[test]
fn verified_context_debug_output_redacts_authority_values() {
    let claims = caseworker_claims("case-management");
    let rendered = format!("{claims:?}");
    assert!(!rendered.contains("principal-value-never-rendered"));
    assert!(!rendered.contains("case-management"));
    assert!(!rendered.contains("area-a"));
    assert!(rendered.contains("registry_principal"));
}

#[tokio::test]
async fn health_and_readiness_are_operational_and_independent() {
    let harness = Harness::new(false);
    let health = harness.send(Method::GET, "/healthz", None).await;
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(body_json(health).await, json!({"status": "alive"}));

    let not_ready = harness.send(Method::GET, "/ready", None).await;
    assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(not_ready).await["code"], "runtime.not_ready");

    harness.readiness.0.store(true, Ordering::SeqCst);
    let ready = harness.send(Method::GET, "/ready", None).await;
    assert_eq!(ready.status(), StatusCode::OK);
    assert_eq!(body_json(ready).await, json!({"status": "ready"}));
    assert_eq!(harness.records.calls(), 0);
}

#[tokio::test]
async fn profile_and_resource_concealment_complete_before_record_io() {
    let harness = Harness::new(true);
    let anonymous_protected = harness
        .send(
            Method::GET,
            "/v1/records/notes/00000000-0000-4000-8000-000000000001",
            None,
        )
        .await;
    let wrong_purpose = caseworker_claims("another-purpose");
    let unauthorized = harness
        .send(
            Method::GET,
            "/v1/records/cases/00000000-0000-4000-8000-000000000001?accessProfile=caseworker",
            Some(wrong_purpose),
        )
        .await;
    let unknown_profile = harness
        .send(
            Method::GET,
            "/v1/records/cases/00000000-0000-4000-8000-000000000001?accessProfile=missing",
            Some(caseworker_claims("case-management")),
        )
        .await;
    let unknown_resource = harness
        .send(
            Method::GET,
            "/v1/records/unknown/00000000-0000-4000-8000-000000000001?accessProfile=caseworker",
            Some(caseworker_claims("case-management")),
        )
        .await;

    assert_eq!(unauthorized.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown_profile.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown_resource.status(), StatusCode::NOT_FOUND);
    assert_eq!(anonymous_protected.status(), StatusCode::NOT_FOUND);
    for response in [
        &anonymous_protected,
        &unauthorized,
        &unknown_profile,
        &unknown_resource,
    ] {
        assert!(response.headers().get("link").is_none());
        assert!(response.headers().get("content-location").is_none());
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        let headers = format!("{:?}", response.headers());
        assert!(!headers.contains("registry-record"));
        assert!(!headers.contains("schemas"));
        assert!(!headers.contains("contexts"));
    }
    let anonymous_protected = problem_shape(anonymous_protected).await;
    let unauthorized = problem_shape(unauthorized).await;
    assert_eq!(anonymous_protected, unauthorized);
    assert_eq!(unauthorized, problem_shape(unknown_profile).await);
    assert_eq!(unauthorized, problem_shape(unknown_resource).await);
    assert_eq!(unauthorized["code"], "resource.not_found");
    assert!(!unauthorized.to_string().contains("caseworker"));
    assert!(!unauthorized.to_string().contains("another-purpose"));
    assert_eq!(harness.records.calls(), 0);

    let fallback_claim = VerifiedRequestClaims::authenticated(
        "sub",
        "principal-value-never-rendered",
        BTreeSet::from(["registry.read".to_owned()]),
        Some("case-management".to_owned()),
        BTreeMap::new(),
    )
    .expect("verified claim fixture");
    let fallback = harness
        .send(
            Method::GET,
            "/v1/records/cases/00000000-0000-4000-8000-000000000001?accessProfile=caseworker",
            Some(fallback_claim),
        )
        .await;
    assert_eq!(fallback.status(), StatusCode::NOT_FOUND);
    assert_eq!(harness.records.calls(), 0);
}

#[tokio::test]
async fn projection_can_only_reduce_the_authorized_profile() {
    let harness = Harness::new(true);
    let public = harness
        .send(
            Method::GET,
            "/v1/records/cases/00000000-0000-4000-8000-000000000001?$select=label",
            None,
        )
        .await;
    assert_eq!(public.status(), StatusCode::OK);
    let public = body_json(public).await;
    assert_eq!(public["data"], json!({"label": "Visible label"}));
    assert!(!public.to_string().contains("DO-NOT-LEAK"));

    let public_list = harness
        .send(Method::GET, "/v1/records/cases?$select=label", None)
        .await;
    assert_eq!(public_list.status(), StatusCode::OK);
    let public_list = body_json(public_list).await;
    assert_eq!(
        public_list["items"][0]["data"],
        json!({"label": "Visible label"})
    );
    assert!(!public_list.to_string().contains("DO-NOT-LEAK"));
    let list_request = harness.records.last_request();
    assert_eq!(
        list_request.selected_fields,
        BTreeSet::from(["label".to_owned()])
    );
    assert_eq!(list_request.maximum_records, 101);

    let before = harness.records.calls();
    let caller_limit = harness
        .send(Method::GET, "/v1/records/cases?$top=101", None)
        .await;
    assert_eq!(caller_limit.status(), StatusCode::BAD_REQUEST);
    assert_eq!(harness.records.calls(), before);

    let widening = harness
        .send(
            Method::GET,
            "/v1/records/cases/00000000-0000-4000-8000-000000000001?$select=secret",
            None,
        )
        .await;
    assert_eq!(widening.status(), StatusCode::NOT_FOUND);
    assert_eq!(harness.records.calls(), before);

    let protected = harness
        .send(
            Method::GET,
            "/v1/records/cases/00000000-0000-4000-8000-000000000001?accessProfile=caseworker&$select=label,secret",
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(protected.status(), StatusCode::OK);
    assert_eq!(
        body_json(protected).await["data"],
        json!({"label": "Visible label", "secret": "DO-NOT-LEAK"})
    );
    let request = harness.records.last_request();
    assert_eq!(request.context.selected_profile(), "caseworker");
    assert_eq!(request.context.purpose(), Some("case-management"));
    assert_eq!(request.context.row_boundaries().len(), 1);
    assert_eq!(
        request.selected_fields,
        BTreeSet::from(["label".to_owned(), "secret".to_owned()])
    );
    assert_eq!(request.maximum_records, 1);
    assert_eq!(request.context.row_boundaries()[0].field(), "jurisdiction");
    assert_eq!(
        request.context.row_boundaries()[0].values(),
        &BTreeSet::from(["area-a".to_owned(), "area-b".to_owned()])
    );
}

#[tokio::test]
async fn discovery_surfaces_share_caller_filtered_routes_and_fields() {
    let harness = Harness::new(true);
    let public_openapi = body_json(harness.send(Method::GET, "/openapi.json", None).await).await;
    assert!(public_openapi["paths"].get("/v1/records/cases").is_some());
    assert!(public_openapi["paths"].get("/v1/records/notes").is_none());
    assert_eq!(
        public_openapi["paths"]["/v1/records/cases"]["get"]["x-registry-queryKind"],
        "list"
    );
    assert_eq!(
        query_parameter_names(&public_openapi["paths"]["/v1/records/cases"]["get"]["parameters"]),
        [
            "$count",
            "$filter",
            "$orderby",
            "$select",
            "$skiptoken",
            "$top",
            "Accept",
            "accessProfile",
            "traceparent",
        ]
    );
    assert_eq!(
        public_openapi["paths"]["/v1/records/cases"]["get"]["security"],
        json!([{}])
    );
    assert!(
        public_openapi["paths"]["/v1/records/cases"]["get"]["responses"]["200"]["headers"]
            .get("traceparent")
            .is_some()
    );
    assert!(
        public_openapi["paths"]["/v1/records/cases"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]
            .get("count")
            .is_some()
    );
    assert!(
        public_openapi["components"]["schemas"]["Problem"]["required"]
            .as_array()
            .expect("Problem required is an array")
            .contains(&json!("traceId"))
    );
    let page_size = public_openapi["paths"]["/v1/records/cases"]["get"]["parameters"]
        .as_array()
        .expect("query parameters are rendered")
        .iter()
        .find(|parameter| parameter["name"] == "$top")
        .expect("$top parameter is rendered");
    assert_eq!(page_size["required"], false);
    assert_eq!(
        page_size["schema"],
        json!({"type": "integer", "minimum": 1, "maximum": 100})
    );
    assert_eq!(
        public_openapi["components"]["schemas"]["case"]["properties"],
        json!({"label": {"type": "string", "minLength": 0, "maxLength": 100}})
    );
    assert_no_mutation_methods(&public_openapi);

    let public_metadata = body_json(harness.send(Method::GET, "/v1/registry", None).await).await;
    assert_eq!(public_metadata["entities"].as_array().unwrap().len(), 1);
    assert_eq!(
        public_metadata["entities"][0]["readableFields"],
        json!(["label"])
    );
    assert_eq!(
        public_metadata["entities"][0]["operations"],
        json!([
            {"operation": "get", "accessProfile": "public"},
            {"operation": "list", "accessProfile": "public"}
        ])
    );

    let public_schema = body_json(harness.send(Method::GET, "/v1/schemas/case", None).await).await;
    assert!(public_schema["properties"].get("label").is_some());
    assert!(public_schema["properties"].get("secret").is_none());

    let protected_openapi = body_json(
        harness
            .send(
                Method::GET,
                "/openapi.json?accessProfile=caseworker",
                Some(caseworker_claims("case-management")),
            )
            .await,
    )
    .await;
    assert!(protected_openapi["paths"]
        .get("/v1/records/notes")
        .is_some());
    assert!(
        protected_openapi["components"]["schemas"]["case"]["properties"]
            .get("secret")
            .is_some()
    );
    assert_eq!(
        protected_openapi["paths"]["/v1/records/cases"]["get"]["security"],
        json!([{"bearerAuth": []}])
    );
    assert_no_mutation_methods(&protected_openapi);
    assert_eq!(harness.records.calls(), 0);
}

#[tokio::test]
async fn discovery_schema_uses_compiled_api_names_without_widening_disclosure() {
    let harness = Harness::from_project(LOGICAL_SCHEMA_PROJECT, true);

    let schema = body_json(
        harness
            .send(Method::GET, "/v1/schemas/logical-record", None)
            .await,
    )
    .await;
    assert_eq!(
        schema["properties"],
        json!({
            "householdCode": {"type": "string", "minLength": 0, "maxLength": 64},
            "householdKind": {
                "type": "string",
                "enum": ["single", "extended"],
                "x-registry-vocabulary": "household-kind"
            }
        })
    );
    assert_eq!(
        schema["required"],
        json!(["householdCode", "householdKind"])
    );

    let openapi = body_json(harness.send(Method::GET, "/openapi.json", None).await).await;
    assert_eq!(openapi["components"]["schemas"]["logical-record"], schema);
    let rendered = openapi.to_string();
    for concealed in [
        "household-code",
        "household-kind-code",
        "private-canary-field",
        "privateCanary",
    ] {
        assert!(
            !rendered.contains(concealed),
            "discovery leaked concealed or internal field name {concealed}"
        );
    }
    assert_eq!(harness.records.calls(), 0);
}

#[tokio::test]
async fn lower_camel_select_resolves_only_compiled_authorized_api_names() {
    let harness = Harness::from_project(LOGICAL_SCHEMA_PROJECT, true);

    let selected = harness
        .send(
            Method::GET,
            "/v1/records/logical-records/00000000-0000-4000-8000-000000000001?$select=householdCode,householdKind",
            None,
        )
        .await;
    assert_eq!(selected.status(), StatusCode::OK);
    assert_eq!(
        harness.records.last_request().selected_fields,
        BTreeSet::from([
            "household-code".to_owned(),
            "household-kind-code".to_owned(),
        ])
    );

    let before = harness.records.calls();
    for uri in [
        "/v1/records/logical-records/00000000-0000-4000-8000-000000000001?$select=unknownCanary",
        "/v1/records/logical-records/00000000-0000-4000-8000-000000000001?$select=privateCanary",
        "/v1/records/logical-records/00000000-0000-4000-8000-000000000001?$select=household-code",
    ] {
        let refused = harness.send(Method::GET, uri, None).await;
        assert_eq!(refused.status(), StatusCode::NOT_FOUND, "{uri}");
        let problem = body_json(refused).await;
        assert_eq!(problem["code"], "resource.not_found");
        let rendered = problem.to_string();
        assert!(!rendered.contains("unknownCanary"));
        assert!(!rendered.contains("privateCanary"));
        assert!(!rendered.contains("household-code"));
    }
    assert_eq!(harness.records.calls(), before);

    let duplicate = harness
        .send(
            Method::GET,
            "/v1/records/logical-records/00000000-0000-4000-8000-000000000001?$select=householdCode,householdCode",
            None,
        )
        .await;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let duplicate = body_json(duplicate).await;
    assert_eq!(duplicate["code"], "query.invalid");
    assert!(!duplicate.to_string().contains("householdCode"));
    assert_eq!(harness.records.calls(), before);
}

#[tokio::test]
async fn caller_filtered_discovery_conceals_counts_vocabularies_events_queries_and_every_metadata_surface(
) {
    let project =
        parse_project_yaml(DISCOVERY_MATRIX_PROJECT.as_bytes()).expect("matrix project parses");
    let registry = Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring).expect("matrix project compiles"),
    );
    let protected = registry
        .entities()
        .get("protected-ledger")
        .expect("protected entity is compiled");
    match &protected.fields["classified-status"].field_type {
        registry_breg::contract::FieldTypeSource::VocabularyCode { vocabulary, values } => {
            assert_eq!(vocabulary, "classified-status-vocabulary");
            assert_eq!(values, &["sealed-canary-value", "retired-canary-value"]);
        }
        _ => panic!("protected vocabulary field retains its closed type"),
    }
    assert!(protected.events.contains_key("classified-created-event"));
    assert_eq!(registry.event_deliveries().deliveries.len(), 1);
    assert_eq!(
        registry.event_deliveries().deliveries[0].destination_id,
        "classified-operations-destination"
    );
    assert_eq!(
        registry
            .queries()
            .operations
            .iter()
            .filter(|query| query.entity_id == "protected-ledger")
            .map(|query| query.id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "records.protected-ledger.caseworker.as-of",
            "records.protected-ledger.caseworker.current",
            "records.protected-ledger.caseworker.list",
        ])
    );

    let records = Arc::new(RecordingReadService::default());
    let app = router(Arc::new(HttpService::new(
        registry.clone(),
        read_identity(),
        records.clone(),
        Arc::new(ControlledReadiness(AtomicBool::new(true))),
        cursor_codec(),
    )));

    let public_openapi = body_json(send_to(&app, Method::GET, "/openapi.json", None).await).await;
    assert_eq!(
        public_openapi["paths"]
            .as_object()
            .expect("public paths")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "/v1/records/public-records",
            "/v1/records/public-records/{record_id}",
        ])
    );
    assert_eq!(
        public_openapi["components"]["schemas"]
            .as_object()
            .expect("public schemas")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["Problem", "public-record"])
    );
    assert_eq!(
        public_openapi["paths"]["/v1/records/public-records"]["get"]["x-registry-accessProfile"],
        "public"
    );
    assert_eq!(
        public_openapi["components"]["schemas"]["public-record"]["properties"],
        json!({"label": {"type": "string", "minLength": 0, "maxLength": 100}})
    );
    let public_metadata = body_json(send_to(&app, Method::GET, "/v1/registry", None).await).await;
    assert_eq!(public_metadata["entities"].as_array().unwrap().len(), 1);
    let metadata_artifact = registry
        .artifacts()
        .get(REGISTRY_METADATA_ARTIFACT_PATH)
        .expect("compiler emits a canonical metadata artifact");
    let metadata_artifact =
        parse_json_strict(&metadata_artifact.bytes).expect("metadata artifact is strict JSON");
    assert!(metadata_artifact.get("revision").is_none());
    assert_eq!(metadata_artifact["registryId"], "discovery-matrix");
    assert_eq!(public_metadata["revision"], registry.revision());
    assert_eq!(
        public_metadata["entities"][0],
        metadata_response_from_inventory(&registry, "public-record", "public")
    );
    let public_schema =
        body_json(send_to(&app, Method::GET, "/v1/schemas/public-record", None).await).await;
    assert_eq!(public_schema["properties"].as_object().unwrap().len(), 1);
    assert_eq!(
        public_schema["properties"],
        json!({"label": {"type": "string", "minLength": 0, "maxLength": 100}})
    );

    for document in [&public_openapi, &public_metadata, &public_schema] {
        let rendered = serde_json::to_string(document).expect("discovery document serializes");
        for canary in [
            "protected-ledger",
            "classified-records",
            "restricted-canary-field",
            "classified-status-vocabulary",
            "sealed-canary-value",
            "retired-canary-value",
            "classified-created-event",
            "classified-operations-destination",
            "records.protected-ledger.caseworker.list",
            "records.protected-ledger.caseworker.current",
            "records.protected-ledger.caseworker.as-of",
        ] {
            assert!(
                !rendered.contains(canary),
                "public discovery leaked {canary}"
            );
        }
    }

    let authorized_claims = Some(caseworker_claims("case-management"));
    let protected_openapi = body_json(
        send_to(
            &app,
            Method::GET,
            "/openapi.json?accessProfile=caseworker",
            authorized_claims.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(
        protected_openapi["paths"]
            .as_object()
            .expect("caseworker paths")
            .len(),
        6
    );
    for path in [
        "/v1/records/classified-records",
        "/v1/records/classified-records/{record_id}",
        "/v1/records/classified-records:current",
        "/v1/records/classified-records:as-of",
    ] {
        assert!(protected_openapi["paths"].get(path).is_some(), "{path}");
        assert_eq!(
            protected_openapi["paths"][path]["get"]["x-registry-accessProfile"],
            "caseworker"
        );
    }
    assert_eq!(
        protected_openapi["paths"]["/v1/records/classified-records:current"]["get"]
            ["x-registry-queryKind"],
        "current"
    );
    assert_eq!(
        protected_openapi["paths"]["/v1/records/classified-records:as-of"]["get"]
            ["x-registry-queryKind"],
        "as_of"
    );
    assert_eq!(
        protected_openapi["components"]["schemas"]["protected-ledger"]["properties"]
            ["classifiedStatus"],
        json!({
            "type": "string",
            "enum": ["sealed-canary-value", "retired-canary-value"],
            "x-registry-vocabulary": "classified-status-vocabulary"
        })
    );
    assert!(protected_openapi["paths"]
        .as_object()
        .expect("caseworker paths")
        .values()
        .flat_map(|path| path.as_object().expect("path methods").values())
        .all(|operation| operation["x-registry-accessProfile"] == "caseworker"));
    let protected_metadata = body_json(
        send_to(
            &app,
            Method::GET,
            "/v1/registry?accessProfile=caseworker",
            authorized_claims.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(protected_metadata["entities"].as_array().unwrap().len(), 2);
    assert!(protected_metadata["entities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|entity| entity["operations"].as_array().unwrap())
        .all(|operation| operation["accessProfile"] == "caseworker"));
    let protected_ledger_metadata = protected_metadata["entities"]
        .as_array()
        .expect("protected metadata entities")
        .iter()
        .find(|entity| entity["id"] == "protected-ledger")
        .expect("protected-ledger metadata is visible to caseworker");
    assert_eq!(
        protected_ledger_metadata,
        &metadata_response_from_inventory(&registry, "protected-ledger", "caseworker")
    );
    let protected_schema = body_json(
        send_to(
            &app,
            Method::GET,
            "/v1/schemas/protected-ledger?accessProfile=caseworker",
            authorized_claims.clone(),
        )
        .await,
    )
    .await;
    assert_eq!(
        protected_schema["properties"]["classifiedStatus"],
        json!({
            "type": "string",
            "enum": ["sealed-canary-value", "retired-canary-value"],
            "x-registry-vocabulary": "classified-status-vocabulary"
        })
    );

    let authorized_rendered =
        serde_json::to_string(&[protected_openapi, protected_metadata, protected_schema])
            .expect("authorized discovery serializes");
    for omitted in [
        "classified-created-event",
        "classified-operations-destination",
        "records.protected-ledger.caseworker.list",
        "records.protected-ledger.caseworker.current",
        "records.protected-ledger.caseworker.as-of",
    ] {
        assert!(
            !authorized_rendered.contains(omitted),
            "unapproved inventory surface exposed {omitted}"
        );
    }

    let missing_profile_response = send_to(
        &app,
        Method::GET,
        "/openapi.json?accessProfile=missing-profile-canary",
        authorized_claims.clone(),
    )
    .await;
    assert_eq!(missing_profile_response.status(), StatusCode::NOT_FOUND);
    let missing_profile = problem_shape(missing_profile_response).await;
    for uri in [
        "/openapi.json?accessProfile=caseworker",
        "/v1/registry?accessProfile=caseworker",
        "/v1/schemas/public-record?accessProfile=caseworker",
        "/v1/schemas/protected-ledger?accessProfile=caseworker",
    ] {
        let response = send_to(
            &app,
            Method::GET,
            uri,
            Some(caseworker_claims("forbidden-purpose-canary")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(problem_shape(response).await, missing_profile, "{uri}");
    }

    for uri in ["/v1/vocabularies", "/v1/events", "/v1/queries"] {
        for claims in [None, authorized_claims.clone()] {
            let response = send_to(&app, Method::GET, uri, claims).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(problem_shape(response).await, missing_profile, "{uri}");
        }
    }
    let refusal = serde_json::to_string(&missing_profile).expect("refusal serializes");
    for canary in [
        "missing-profile-canary",
        "forbidden-purpose-canary",
        "protected-ledger",
        "classified-status-vocabulary",
        "classified-created-event",
        "records.protected-ledger.caseworker.list",
    ] {
        assert!(!refusal.contains(canary));
    }
    assert_eq!(records.calls(), 0);
}

#[tokio::test]
async fn real_router_serves_only_authorized_explicit_revision_routes() {
    let (app, revisions) = revision_harness();
    let record_id = "00000000-0000-4000-8000-000000000001";
    let list_path = format!("/v1/records/cases/{record_id}/revisions");
    let detail_path = format!("{list_path}/1");

    let public = send_to(&app, Method::GET, &list_path, None).await;
    assert_eq!(public.status(), StatusCode::NOT_FOUND);
    assert_eq!(revisions.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        revisions.refusals.load(Ordering::SeqCst),
        0,
        "a refusal that names no principal is counted, not journaled"
    );

    let wrong_purpose = send_to(
        &app,
        Method::GET,
        &list_path,
        Some(caseworker_claims("wrong-purpose")),
    )
    .await;
    assert_eq!(wrong_purpose.status(), StatusCode::NOT_FOUND);
    assert_eq!(revisions.calls.load(Ordering::SeqCst), 0);

    let extra_query = send_to(
        &app,
        Method::GET,
        &format!("{list_path}?accessProfile=caseworker&$top=1"),
        Some(caseworker_claims("case-management")),
    )
    .await;
    assert_eq!(extra_query.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(extra_query).await["code"], "query.invalid");
    assert_eq!(revisions.calls.load(Ordering::SeqCst), 0);

    let list = send_to(
        &app,
        Method::GET,
        &format!("{list_path}?accessProfile=caseworker"),
        Some(caseworker_claims("case-management")),
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(list.headers()["cache-control"], "no-store");
    let detail = send_to(
        &app,
        Method::GET,
        &format!("{detail_path}?accessProfile=caseworker"),
        Some(caseworker_claims("case-management")),
    )
    .await;
    assert_eq!(detail.status(), StatusCode::OK);
    assert_eq!(revisions.calls.load(Ordering::SeqCst), 2);
    let request_shapes = {
        let requests = revisions.requests.lock().expect("request lock");
        requests
            .iter()
            .map(|request| (request.maximum_records, request.revision))
            .collect::<Vec<_>>()
    };
    assert_eq!(request_shapes, [(100, None), (1, Some(1))]);

    let public_openapi = body_json(send_to(&app, Method::GET, "/openapi.json", None).await).await;
    assert!(public_openapi["paths"]
        .as_object()
        .expect("paths")
        .keys()
        .all(|path| !path.contains("revisions")));
    let protected_openapi = body_json(
        send_to(
            &app,
            Method::GET,
            "/openapi.json?accessProfile=caseworker",
            Some(caseworker_claims("case-management")),
        )
        .await,
    )
    .await;
    assert!(protected_openapi["paths"]
        .get("/v1/records/cases/{record_id}/revisions")
        .is_some());
    assert!(protected_openapi["paths"]
        .get("/v1/records/cases/{record_id}/revisions/{revision}")
        .is_some());
    let protected_metadata = body_json(
        send_to(
            &app,
            Method::GET,
            "/v1/registry?accessProfile=caseworker",
            Some(caseworker_claims("case-management")),
        )
        .await,
    )
    .await;
    let case = protected_metadata["entities"]
        .as_array()
        .expect("entities")
        .iter()
        .find(|entity| entity["id"] == "case")
        .expect("case metadata");
    assert!(case["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .any(|operation| operation["operation"] == "revisions"));
    assert!(revisions.refusals.load(Ordering::SeqCst) >= 2);

    revisions.refusal_fails.store(true, Ordering::SeqCst);
    let audit_failure = send_to(
        &app,
        Method::GET,
        &format!("{list_path}?$top=2"),
        Some(caseworker_claims("case-management")),
    )
    .await;
    assert_eq!(audit_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(audit_failure).await["code"], "source.unavailable");
    assert_eq!(revisions.calls.load(Ordering::SeqCst), 2);
}

fn query_parameter_names(parameters: &Value) -> Vec<String> {
    let mut names = parameters
        .as_array()
        .expect("parameters are an array")
        .iter()
        .map(|parameter| {
            parameter["name"]
                .as_str()
                .expect("parameter has a name")
                .to_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn metadata_response_from_inventory(
    registry: &registry_breg::CompiledRegistry,
    entity_id: &str,
    access_profile: &str,
) -> Value {
    let metadata_entity = registry
        .metadata()
        .entities
        .iter()
        .find(|entity| entity.id == entity_id)
        .expect("compiled metadata entity exists");
    let dataset_identifier = registry
        .entities()
        .get(entity_id)
        .and_then(|entity| entity.primary_dataset.as_deref())
        .expect("compiled metadata entity has one primary dataset");
    let mut operations = BTreeMap::new();
    let mut readable_fields: Option<BTreeSet<String>> = None;
    for entry in metadata_entity
        .entries
        .iter()
        .filter(|entry| entry.access_profile == access_profile)
    {
        operations.insert(entry.operation, entry.access_profile.clone());
        readable_fields = Some(match readable_fields {
            Some(fields) => fields
                .intersection(&entry.readable_fields)
                .cloned()
                .collect(),
            None => entry.readable_fields.clone(),
        });
    }
    json!({
        "id": metadata_entity.id,
        "datasetIdentifier": dataset_identifier,
        "route": metadata_entity.route,
        "operations": operations.into_iter().map(|(operation, access_profile)| json!({
            "operation": operation_name(operation),
            "accessProfile": access_profile,
        })).collect::<Vec<_>>(),
        "readableFields": readable_fields.expect("access profile has metadata entries"),
        "schema": metadata_entity.schema_path,
    })
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Get => "get",
        Operation::List => "list",
        Operation::Lookup => "lookup",
        Operation::Create => "create",
        Operation::Patch => "patch",
        Operation::Tombstone => "tombstone",
        Operation::Batch => "batch",
        Operation::Revisions => "revisions",
        Operation::SubmitRequest => "submit_request",
        Operation::ApproveRequest => "approve_request",
        Operation::RejectRequest => "reject_request",
        Operation::RequestRevision => "request_revision",
        Operation::ReviseRequest => "revise_request",
        Operation::CancelRequest => "cancel_request",
        Operation::ApplyRequest => "apply_request",
        Operation::Invoke => "invoke",
        Operation::Snapshot => "snapshot",
    }
}

#[tokio::test]
async fn runtime_openapi_contract_is_filtered_to_the_selected_acceptance_profile() {
    let source =
        include_str!("../../../products/breg/acceptance/asset-site-placement/registry.yaml");
    let harness = Harness::from_project(source, true);
    let openapi = body_json(
        harness
            .send(
                Method::GET,
                "/openapi.json?accessProfile=site-planner",
                Some(registry_principal_claims("site-planning")),
            )
            .await,
    )
    .await;

    assert_eq!(
        openapi["components"]["securitySchemes"]["bearerAuth"],
        json!({"type": "http", "scheme": "bearer", "bearerFormat": "JWT"})
    );
    assert!(openapi["components"]["schemas"]["Problem"]
        .get("properties")
        .is_some());
    assert_eq!(
        openapi["components"]["schemas"]["Problem"]["required"],
        json!(["type", "title", "status", "detail", "code", "traceId"])
    );
    assert_eq!(
        openapi["paths"]["/v1/records/assets"]["get"]["x-registry-accessProfile"],
        "site-planner"
    );
    assert_eq!(
        openapi["paths"]["/v1/records/assets"]["get"]["security"],
        json!([{"bearerAuth": []}])
    );
    assert!(openapi["paths"]["/v1/records/assets"]["get"]
        .get("x-registry-queryProfile")
        .is_some());
    assert!(openapi["paths"]["/v1/records/assets"]["get"]
        .get("x-registry-queryProfiles")
        .is_none());
    assert_eq!(
        openapi["paths"]["/v1/records/assets"]["get"]["x-registry-queryProfile"]
            ["selectableProperties"],
        json!(["assetCode", "label"])
    );
    assert_eq!(
        query_parameter_names(
            &openapi["paths"]["/v1/records/assets/{record_id}"]["get"]["parameters"]
        ),
        [
            "$select",
            "Accept",
            "accessProfile",
            "record_id",
            "traceparent"
        ]
    );
    let record_operation = &openapi["paths"]["/v1/records/assets/{record_id}"]["get"];
    assert_eq!(
        record_operation["x-registry-responseProfile"],
        "https://id.registrystack.org/profiles/registry-record/v1"
    );
    assert_eq!(
        record_operation["x-registry-responseShape"],
        "RegistryRecordSingleV1"
    );
    let ordinary = &record_operation["responses"]["200"]["content"]["application/json"]["schema"];
    let json_ld = &record_operation["responses"]["200"]["content"]["application/ld+json"]["schema"];
    assert!(ordinary["properties"].get("@context").is_none());
    assert_eq!(
        json_ld["properties"]["@context"]["const"],
        "https://id.registrystack.org/contexts/registry-record/v1"
    );
    assert_eq!(
        ordinary["properties"]["meta"]["properties"],
        json!({
            "registryIdentifier": {"const": "asset-site-placement"},
            "datasetIdentifier": {"const": "asset-site-placement"},
            "entityTypeIdentifier": {"const": "asset-item"}
        })
    );
    assert_eq!(
        ordinary["properties"]["data"]["required"],
        json!(["recordIdentifier", "revisionIdentifier", "domainData"])
    );
    assert!(ordinary.to_string().contains("domainData"));
    assert!(!ordinary.to_string().contains("\"@id\""));
    assert!(!ordinary.to_string().contains("\"@type\""));
    let link = &record_operation["responses"]["200"]["headers"]["Link"];
    assert_eq!(
        link["description"],
        "Emitted only for application/json and application/ld+json Registry Record responses and omitted for application/geo+json. Carries the Registry Record profile and caller-visible entity schema. The describedby target is a relative BReg route and is never derived from Host or forwarded headers."
    );
    assert_eq!(
        link["schema"]["const"],
        "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/asset-item>; rel=\"describedby\""
    );
    assert!(
        openapi["paths"]["/v1/records/assets/{record_id}"]["get"]["responses"]["200"]["headers"]
            .get("ETag")
            .is_some()
    );
    assert!(
        openapi["paths"]["/v1/records/assets/{record_id}"]["get"]["responses"]["200"]["headers"]
            .get("traceparent")
            .is_some()
    );
    assert!(openapi["components"]["schemas"]["asset-item"]["properties"]
        .get("assetClass")
        .is_none());
    assert!(openapi["paths"].get("/v1/records/inspections").is_none());
    assert_eq!(harness.records.calls(), 0);
}

#[tokio::test]
async fn every_compiled_mutation_route_is_absent_from_the_served_router() {
    let harness = Harness::new(true);
    let claims = Some(caseworker_claims("case-management"));
    for (method, uri) in [
        (Method::POST, "/v1/records/cases"),
        (
            Method::PATCH,
            "/v1/records/cases/00000000-0000-4000-8000-000000000001",
        ),
        (
            Method::DELETE,
            "/v1/records/cases/00000000-0000-4000-8000-000000000001",
        ),
        (Method::POST, "/v1/records/cases:batch"),
        (
            Method::GET,
            "/v1/records/cases/00000000-0000-4000-8000-000000000001/revisions",
        ),
        (Method::POST, "/v1/records/notes"),
        (
            Method::PATCH,
            "/v1/records/notes/00000000-0000-4000-8000-000000000001",
        ),
        (
            Method::DELETE,
            "/v1/records/notes/00000000-0000-4000-8000-000000000001",
        ),
    ] {
        let response = harness.send(method, uri, claims.clone()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(body_json(response).await["code"], "resource.not_found");
    }
    assert_eq!(harness.records.calls(), 0);
}

fn caseworker_claims(purpose: &str) -> VerifiedRequestClaims {
    caseworker_claims_with_direct(
        purpose,
        std::iter::empty::<(&'static str, VerifiedClaimValue)>(),
    )
}

fn registry_principal_claims(purpose: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "registry-principal",
        BTreeSet::new(),
        Some(purpose.to_owned()),
        BTreeMap::new(),
    )
    .expect("registry principal claims are valid")
}

fn caseworker_claims_with_direct<I>(purpose: &str, direct_claims: I) -> VerifiedRequestClaims
where
    I: IntoIterator<Item = (&'static str, VerifiedClaimValue)>,
{
    let mut direct = BTreeMap::from([(
        "jurisdictions".to_owned(),
        VerifiedClaimValue::direct_string_set(["area-a", "area-b"]).expect("direct claims"),
    )]);
    for (name, value) in direct_claims {
        direct.insert(name.to_owned(), value);
    }
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "principal-value-never-rendered",
        BTreeSet::from(["registry.read".to_owned()]),
        Some(purpose.to_owned()),
        direct,
    )
    .expect("verified context")
}

fn request_query(request: &RecordReadRequest) -> &registry_breg::api::CompiledReadQuery {
    match &request.kind {
        RecordReadKind::List { plan } | RecordReadKind::Relationship { plan, .. } => plan,
        RecordReadKind::Get { .. } | RecordReadKind::Lookup { .. } => {
            panic!("request did not carry a list query plan")
        }
    }
}

fn single_filter_predicate(
    query: &registry_breg::api::CompiledReadQuery,
) -> &registry_breg::api::ReadFilterPredicate {
    match query.filter.as_ref().expect("query has a filter") {
        registry_breg::api::ReadFilterExpr::Predicate(predicate) => predicate,
        other => panic!("expected one predicate filter, got {other:?}"),
    }
}

fn project_fixture(mut record: Value, selected_fields: &BTreeSet<String>) -> Value {
    record["data"]
        .as_object_mut()
        .expect("fixture data is an object")
        .retain(|field, _| selected_fields.contains(field));
    record
}

fn held(value: Value) -> HeldReadResponse {
    HeldReadResponse::from_json(&value).expect("fake read response serializes")
}

fn held_json_representation(
    value: Value,
    representation: CursorRepresentation,
) -> HeldReadResponse {
    match representation {
        CursorRepresentation::Json => HeldReadResponse::from_json(&value),
        CursorRepresentation::JsonLd => HeldReadResponse::from_json_ld(&value),
        CursorRepresentation::GeoJson => unreachable!("GeoJSON uses its dedicated fake"),
    }
    .expect("fake Registry Record response serializes")
}

fn geojson_feature(record: Value) -> HeldReadResponse {
    let mut properties = record["data"].as_object().cloned().unwrap_or_default();
    let geometry = properties.remove("location").unwrap_or(Value::Null);
    HeldReadResponse::from_geojson(&json!({
        "type": "Feature",
        "id": record["id"],
        "geometry": geometry,
        "properties": properties,
        "registry": {"revision": record["revision"]},
    }))
    .expect("fake GeoJSON feature serializes")
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    bytes.to_vec()
}

async fn body_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&body_bytes(response).await).expect("JSON response")
}

async fn problem_shape(response: axum::response::Response) -> Value {
    let mut problem = body_json(response).await;
    problem
        .as_object_mut()
        .expect("problem response is an object")
        .remove("traceId")
        .expect("problem response carries traceId");
    problem
}

fn assert_no_mutation_methods(document: &Value) {
    for path in document["paths"].as_object().unwrap().values() {
        let methods = path.as_object().unwrap();
        assert!(methods.get("post").is_none());
        assert!(methods.get("patch").is_none());
        assert!(methods.get("delete").is_none());
    }
}

fn metadata_operation<'a>(document: &'a Value, id: &str) -> &'a Value {
    document["operations"]
        .as_array()
        .expect("operation metadata")
        .iter()
        .find(|operation| operation["id"] == id)
        .expect("authorized operation")
}

#[tokio::test]
async fn workspace_metadata_title_fields_prefer_readable_unique_text_or_string_before_generic_fallback(
) {
    let harness = Harness::from_project(METADATA_LABEL_PROJECT, true);
    let document = body_json(harness.send(Method::GET, "/v1/registry", None).await).await;

    let permit_get = metadata_operation(&document, "records.permit.get");
    assert_eq!(
        permit_get["titleFields"],
        json!(["display-token"]),
        "authored manifest identifiers keep precedence over compiled temporal labels"
    );

    let inspection_get = metadata_operation(&document, "records.inspection.get");
    assert_eq!(
        inspection_get["titleFields"],
        json!(["inspection-code"]),
        "readable single-field temporal scopes are preferred over arbitrary readable strings"
    );
    let inspection_current = metadata_operation(&document, "records.inspection.current");
    assert_eq!(inspection_current["query"]["kind"], "current");
    assert_eq!(
        inspection_current["titleFields"],
        json!(["inspection-code"])
    );
    let certificate_get = metadata_operation(&document, "records.certificate.get");
    assert_eq!(
        certificate_get["titleFields"],
        json!(["certificate-code"]),
        "non-temporal readable single-field unique text keys stay above arbitrary readable strings"
    );

    let finding = metadata_operation(&document, "records.finding.get");
    let reference = &finding["fields"][0]["reference"];
    assert_eq!(reference["targetEntity"], "inspection");
    assert!(reference["operations"]
        .as_array()
        .expect("reference operations")
        .iter()
        .any(|operation| operation["labelFields"] == json!(["inspection-code"])));

    let rendered = document.to_string();
    for hidden in [
        "hidden-permit-key",
        "hidden-inspection-key",
        "hidden-certificate-key",
    ] {
        assert!(!rendered.contains(hidden), "metadata leaked {hidden}");
    }

    let redacted = body_json(
        harness
            .send(
                Method::GET,
                "/v1/registry?accessProfile=redacted-reader",
                None,
            )
            .await,
    )
    .await;
    let redacted_inspection = metadata_operation(&redacted, "records.inspection.get");
    assert_eq!(redacted_inspection["titleFields"], json!(["import-source"]));
    assert_eq!(
        redacted_inspection["readableFields"],
        json!(["import-source", "valid-from"])
    );
    let redacted_reference =
        &metadata_operation(&redacted, "records.finding.get")["fields"][0]["reference"];
    assert!(redacted_reference["operations"]
        .as_array()
        .expect("redacted reference operations")
        .iter()
        .all(|operation| operation["labelFields"] == json!(["import-source"])));
    assert!(!redacted.to_string().contains("inspection-code"));
    assert_eq!(harness.records.calls(), 0);
}

#[tokio::test]
async fn workspace_metadata_keeps_route_fields_selectors_and_query_capabilities_separate() {
    let harness = Harness::from_project(LOOKUP_PATH_PROJECT, true);
    let response = harness
        .send(
            Method::GET,
            "/v1/registry?accessProfile=operator",
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(response.headers()["cache-control"], "no-store");
    let document = body_json(response).await;
    assert_eq!(document["metadataVersion"], "1");
    assert!(document["revision"].is_string());
    let path = metadata_operation(&document, "records.household.path.people");
    assert_eq!(path["sourceEntity"], "household");
    assert_eq!(path["responseEntity"], "person");
    assert_eq!(path["readPath"], json!({"id":"people", "label":"People"}));
    assert_eq!(path["readableFields"], json!(["person-code"]));
    assert_eq!(path["fields"][0]["apiName"], "personCode");
    assert_eq!(path["titleFields"], json!(["person-code"]));
    assert_eq!(path["query"]["allowCount"], true);
    assert_eq!(
        path["query"]["filterableFields"][0]["apiName"],
        "personCode"
    );
    assert_eq!(
        path["query"]["sortableFields"][0],
        json!({"id":"person-code","apiName":"personCode","directions":["asc"]})
    );
    assert_eq!(
        path["request"]["queryParameters"],
        json!([
            "$count",
            "$filter",
            "$orderby",
            "$select",
            "$skiptoken",
            "$top"
        ])
    );
    assert_eq!(
        path["query"]["maxPageSize"],
        path["query"]["defaultPageSize"]
    );
    let direct = metadata_operation(&document, "records.person.get");
    assert_eq!(direct["readableFields"], json!(["sensitive-note"]));
    assert_eq!(
        direct["fields"][0]["schema"]["anyOf"][1],
        json!({"type":"null"})
    );
    assert_eq!(direct["request"]["queryParameters"], json!(["$select"]));
    assert_eq!(direct["createWritableFields"], json!([]));
    assert_eq!(direct["patchWritableFields"], json!([]));
    assert_eq!(direct["requiredCapabilities"], json!([]));
    let lookup = metadata_operation(&document, "records.household.lookup");
    assert_eq!(lookup["selectors"].as_array().unwrap().len(), 2);
    assert_eq!(lookup["selectors"][0]["valueOrigin"], "request");
    assert_eq!(
        lookup["selectors"][0]["requestFields"],
        json!(["householdCode"])
    );
    assert_eq!(
        lookup["selectors"][0]["fields"][0]["schema"],
        json!({"type":"string","minLength":0,"maxLength":64})
    );
    assert_eq!(lookup["request"]["queryParameters"], json!(["$select"]));
    let openapi = body_json(
        harness
            .send(
                Method::GET,
                "/openapi.json?accessProfile=operator",
                Some(caseworker_claims("case-management")),
            )
            .await,
    )
    .await;
    let query_parameters = openapi["paths"][lookup["path"].as_str().unwrap()]["post"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|parameter| parameter["in"] == "query" && parameter["name"] != "accessProfile")
        .map(|parameter| parameter["name"].clone())
        .collect::<Vec<_>>();
    assert_eq!(
        lookup["request"]["queryParameters"],
        json!(query_parameters)
    );
    let rendered = document.to_string();
    for hidden in [
        "private-note",
        "privateNote",
        "by-private-note",
        "sourceRef",
        "targetRef",
        "claimMapping",
        "physicalName",
        "processingFields",
    ] {
        assert!(!rendered.contains(hidden), "metadata leaked {hidden}");
    }
    assert_eq!(harness.records.calls(), 0);
}

#[tokio::test]
async fn workspace_metadata_lookup_claim_origin_exposes_no_private_claim_mapping() {
    let harness = Harness::from_project(LOOKUP_PATH_PROJECT, true);
    let claims = caseworker_claims_with_direct(
        "case-management",
        [
            (
                "household_id",
                VerifiedClaimValue::direct_string("00000000-0000-4000-8000-000000000001").unwrap(),
            ),
            (
                "household_code",
                VerifiedClaimValue::direct_string("PRIVATE-SELECTOR-VALUE").unwrap(),
            ),
        ],
    );
    let document = body_json(
        harness
            .send(
                Method::GET,
                "/v1/registry?accessProfile=viewer",
                Some(claims),
            )
            .await,
    )
    .await;
    let lookup = metadata_operation(&document, "records.household.lookup");
    assert_eq!(lookup["selectors"].as_array().unwrap().len(), 1);
    assert_eq!(lookup["selectors"][0]["valueOrigin"], "verified_claim");
    assert_eq!(lookup["request"]["queryParameters"], json!(["$select"]));
    assert_eq!(lookup["selectors"][0]["requestFields"], json!([]));
    assert_eq!(
        lookup["selectors"][0]["fields"][0]["apiName"],
        "householdCode"
    );
    let rendered = document.to_string();
    for hidden in [
        "household_id",
        "household_code",
        "PRIVATE-SELECTOR-VALUE",
        "administrative-area",
        "by-local-reference",
        "claimMapping",
        "path.people",
    ] {
        assert!(!rendered.contains(hidden), "metadata leaked {hidden}");
    }
    assert_eq!(document["operations"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn workspace_references_require_independent_same_profile_target_operations() {
    let source = LOOKUP_PATH_PROJECT.replace("      - entity: person\n        operations: [get, list]", "      - entity: membership\n        operations: [get]\n        readableFields: [person]\n      - entity: person\n        operations: [get, list]");
    let harness = Harness::from_project(&source, true);
    let document = body_json(
        harness
            .send(
                Method::GET,
                "/v1/registry?accessProfile=operator",
                Some(caseworker_claims("case-management")),
            )
            .await,
    )
    .await;
    let membership = metadata_operation(&document, "records.membership.get");
    assert_eq!(membership["fields"].as_array().unwrap().len(), 1);
    let reference = &membership["fields"][0]["reference"];
    assert_eq!(reference["targetEntity"], "person");
    assert_eq!(reference["manualEntry"], true);
    assert_eq!(reference["operations"].as_array().unwrap().len(), 2);
    for operation in reference["operations"].as_array().unwrap() {
        assert_eq!(operation["accessProfile"], "operator");
        assert_eq!(operation["labelFields"], json!(["sensitive-note"]));
        assert_ne!(operation["operationId"], "records.household.path.people");
    }
    let path_only = source.replace("      - entity: person\n        operations: [get, list]\n        readableFields: [sensitive-note]\n        filterableFields: [sensitive-note]\n        sortableFields: [sensitive-note]\n", "");
    let harness = Harness::from_project(&path_only, true);
    let document = body_json(
        harness
            .send(
                Method::GET,
                "/v1/registry?accessProfile=operator",
                Some(caseworker_claims("case-management")),
            )
            .await,
    )
    .await;
    let reference =
        &metadata_operation(&document, "records.membership.get")["fields"][0]["reference"];
    assert_eq!(reference, &json!({"manualEntry":true,"operations":[]}));
    assert!(document["operations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|operation| operation["readPath"]["id"] == "people"));
    // The no-profile request can have different compiled defaults per route.
    // Even a visible direct operation in another profile cannot label this reference.
    let other_profile = format!("{path_only}      - entity: person\n        operations: [get, list]\n        readableFields: [sensitive-note]\n");
    let harness = Harness::from_project(&other_profile, true);
    let document = body_json(
        harness
            .send(
                Method::GET,
                "/v1/registry",
                Some(caseworker_claims("case-management")),
            )
            .await,
    )
    .await;
    assert_eq!(
        metadata_operation(&document, "records.person.get")["accessProfile"],
        "viewer"
    );
    assert_eq!(
        metadata_operation(&document, "records.membership.get")["fields"][0]["reference"],
        json!({"manualEntry":true,"operations":[]})
    );
}

#[tokio::test]
async fn workspace_temporal_capabilities_and_no_store_cover_success_and_refusal() {
    let harness = Harness::from_project(DISCOVERY_MATRIX_PROJECT, true);
    let document = body_json(
        harness
            .send(
                Method::GET,
                "/v1/registry?accessProfile=caseworker",
                Some(caseworker_claims("case-management")),
            )
            .await,
    )
    .await;
    let as_of = document["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["query"]["kind"] == "as_of")
        .unwrap();
    assert_eq!(as_of["query"]["temporal"]["parameter"], "asOf");
    assert_eq!(as_of["query"]["temporal"]["required"], true);
    assert!(as_of["request"]["queryParameters"]
        .as_array()
        .unwrap()
        .contains(&json!("asOf")));
    for uri in [
        "/v1/registry",
        "/openapi.json",
        "/v1/schemas/public-record",
        "/v1/records/public-records",
        "/v1/records/public-records/00000000-0000-4000-8000-000000000001",
        "/v1/registry?accessProfile=unknown",
        "/v1/schemas/protected-ledger",
        "/v1/records/public-records?$top=0",
        "/missing",
    ] {
        let response = harness.send(Method::GET, uri, None).await;
        assert_eq!(response.headers()["cache-control"], "no-store", "{uri}");
        assert!(response.headers().contains_key("traceparent"));
    }
}
