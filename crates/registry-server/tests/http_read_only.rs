// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use registry_platform_canonical_json::parse_json_strict;
use registry_server::api::{
    router, HeldReadResponse, HttpService, ReadRuntimeIdentity, ReadServiceError, ReadinessProbe,
    RecordReadRequest, RecordReadService, RevisionReadRefusal, RevisionReadRequest,
    RevisionReadService, ServiceFuture, VerifiedClaimValue, VerifiedRequestClaims,
};
use registry_server::artifacts::REGISTRY_METADATA_ARTIFACT_PATH;
use registry_server::contract::Operation;
use registry_server::cursor::CursorCodec;
use registry_server::{compile_project, parse_project_yaml, CompileProfile};
use serde_json::{json, Value};
use tower::Service as _;
use zeroize::Zeroizing;

const PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: read-surface
  version: 0.1.0
  defaultLanguage: en
entities:
  - id: case
    route: cases
    mutationMode: mutable
    tombstone: true
    batch: {maximumItems: 10, maximumBytes: 65536}
    classification: public
    fields:
      - {id: label, type: string, required: true, maxLength: 100, classification: public}
      - {id: secret, type: string, required: true, maxLength: 100, classification: restricted}
      - {id: jurisdiction, type: string, required: true, maxLength: 32, classification: internal}
    accessProfiles:
      - id: public
        default: true
        anonymous: true
        operations: [get, list]
        readableFields: [label]
        filterableFields: [label]
        sortableFields: [label]
      - id: caseworker
        principalClaim: registry_principal
        requiredScopes: [registry.read]
        requiredPurposes: [case-management]
        operations: [create, get, list, patch, tombstone, batch, revisions]
        readableFields: [label, secret, jurisdiction]
        writableFields: [label, secret, jurisdiction]
        filterableFields: [label, jurisdiction]
        sortableFields: [label]
        rowBoundaries:
          - {field: jurisdiction, claim: jurisdictions, operator: in}
  - id: protected-note
    route: notes
    mutationMode: create_only
    classification: restricted
    fields:
      - {id: text, type: text, required: true, maxLength: 200, classification: restricted}
    accessProfiles:
      - id: caseworker
        principalClaim: registry_principal
        requiredScopes: [registry.read]
        requiredPurposes: [case-management]
        operations: [create, get, list]
        readableFields: [text]
        writableFields: [text]
"#;

const DISCOVERY_MATRIX_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: discovery-matrix
  version: 1
  defaultLanguage: en
entities:
  - id: public-record
    route: public-records
    mutationMode: mutable
    classification: public
    fields:
      - {id: label, type: string, required: true, maxLength: 100, classification: public}
      - {id: restricted-canary-field, type: string, maxLength: 100, classification: restricted}
    accessProfiles:
      - id: public
        default: true
        anonymous: true
        operations: [get, list]
        readableFields: [label]
        filterableFields: [label]
        sortableFields: [label]
      - id: caseworker
        principalClaim: registry_principal
        requiredScopes: [registry.read]
        requiredPurposes: [case-management]
        operations: [get, list]
        readableFields: [label, restricted-canary-field]
        filterableFields: [label]
        sortableFields: [label]
  - id: protected-ledger
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
      - id: caseworker
        principalClaim: registry_principal
        requiredScopes: [registry.read]
        requiredPurposes: [case-management]
        operations: [get, list]
        readableFields: [classified-status, valid-from, valid-to]
        filterableFields: [classified-status]
        sortableFields: [valid-from]
vocabularies:
  - id: classified-status-vocabulary
    values: [sealed-canary-value, retired-canary-value]
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
            "/v1/records/cases?fields=label&filter=label:prefix:Visible&sort=label&pageSize=25",
            None,
        )
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(accepted.headers()["cache-control"], "no-store");
    let request = harness.records.last_request();
    let query = request.query.expect("list request carries compiled query");
    assert_eq!(query.route_id, "records.case.list");
    assert_eq!(query.query_operation_id, "records.case.public.list");
    assert_eq!(query.page_size, 25);
    assert_eq!(request.maximum_records, 26);
    assert_eq!(query.sort.as_deref(), Some("label"));
    assert_eq!(query.filters.len(), 1);
    assert_eq!(query.filters[0].field, "label");
    assert_eq!(
        query.filters[0].operator,
        registry_server::model::CompiledQueryFilterOperator::Prefix
    );

    let before = harness.records.calls();
    let bad_operator = harness
        .send(
            Method::GET,
            "/v1/records/cases?filter=label:range:a..z",
            None,
        )
        .await;
    assert_eq!(bad_operator.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(bad_operator).await["code"], "query.invalid");
    assert_eq!(harness.records.calls(), before);
}

#[tokio::test]
async fn repeated_in_filters_are_one_deterministic_finite_set() {
    let harness = Harness::new(true);
    let accepted = harness
        .send(
            Method::GET,
            "/v1/records/cases?accessProfile=caseworker&filter=jurisdiction:in:area-b&filter=jurisdiction:in:area-a",
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    let query = harness
        .records
        .last_request()
        .query
        .expect("list request carries compiled query");
    assert_eq!(query.filters.len(), 1);
    assert_eq!(query.filters[0].field, "jurisdiction");
    assert_eq!(
        query.filters[0].values,
        vec!["area-a".to_owned(), "area-b".to_owned()]
    );

    let mixed = harness
        .send(
            Method::GET,
            "/v1/records/cases?accessProfile=caseworker&filter=jurisdiction:in:area-a&filter=jurisdiction:equals:area-a",
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(mixed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(mixed).await["code"], "query.invalid");
}

#[tokio::test]
async fn continuation_requests_refuse_query_overrides_before_record_io() {
    let harness = Harness::new(true);
    let before = harness.records.calls();
    let response = harness
        .send(
            Method::GET,
            "/v1/records/cases?cursor=opaque-token&fields=label",
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
        .send(Method::GET, "/v1/records/cases?filter=label:equals", None)
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(response).await["code"], "source.unavailable");
    assert_eq!(harness.records.calls(), 0);
    assert_eq!(harness.records.refusal_calls(), 1);
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
        self.record(request);
        Box::pin(async move {
            Ok(Some(held(project_fixture(
                json!({
                    "id": "record-1",
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

    fn list(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        let selected_fields = request.selected_fields.clone();
        let maximum_records = request.maximum_records;
        self.record(request);
        Box::pin(async move {
            let mut records = vec![project_fixture(
                json!({
                    "id": "record-1",
                    "revision": 1,
                    "data": {
                            "label": "Visible label",
                            "secret": "DO-NOT-LEAK",
                            "jurisdiction": "area-a"
                    }
                }),
                &selected_fields,
            )];
            records.truncate(maximum_records);
            Ok(held(json!({"items": records})))
        })
    }

    fn refusal(
        &self,
        _request: registry_server::api::RecordReadRefusal,
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
        let project = parse_project_yaml(PROJECT.as_bytes()).expect("project parses");
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
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("request");
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
    let wrong_purpose = caseworker_claims("another-purpose");
    let unauthorized = harness
        .send(
            Method::GET,
            "/v1/records/cases/record-1?accessProfile=caseworker",
            Some(wrong_purpose),
        )
        .await;
    let unknown_profile = harness
        .send(
            Method::GET,
            "/v1/records/cases/record-1?accessProfile=missing",
            Some(caseworker_claims("case-management")),
        )
        .await;
    let unknown_resource = harness
        .send(
            Method::GET,
            "/v1/records/unknown/record-1?accessProfile=caseworker",
            Some(caseworker_claims("case-management")),
        )
        .await;

    assert_eq!(unauthorized.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown_profile.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown_resource.status(), StatusCode::NOT_FOUND);
    let unauthorized = body_json(unauthorized).await;
    assert_eq!(unauthorized, body_json(unknown_profile).await);
    assert_eq!(unauthorized, body_json(unknown_resource).await);
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
            "/v1/records/cases/record-1?accessProfile=caseworker",
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
        .send(Method::GET, "/v1/records/cases/record-1?fields=label", None)
        .await;
    assert_eq!(public.status(), StatusCode::OK);
    let public = body_json(public).await;
    assert_eq!(public["data"], json!({"label": "Visible label"}));
    assert!(!public.to_string().contains("DO-NOT-LEAK"));

    let public_list = harness
        .send(Method::GET, "/v1/records/cases?fields=label", None)
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
        .send(Method::GET, "/v1/records/cases?pageSize=101", None)
        .await;
    assert_eq!(caller_limit.status(), StatusCode::BAD_REQUEST);
    assert_eq!(harness.records.calls(), before);

    let widening = harness
        .send(
            Method::GET,
            "/v1/records/cases/record-1?fields=secret",
            None,
        )
        .await;
    assert_eq!(widening.status(), StatusCode::NOT_FOUND);
    assert_eq!(harness.records.calls(), before);

    let protected = harness
        .send(
            Method::GET,
            "/v1/records/cases/record-1?accessProfile=caseworker&fields=label,secret",
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
            "accessProfile",
            "cursor",
            "fields",
            "filter",
            "pageSize",
            "sort"
        ]
    );
    let page_size = public_openapi["paths"]["/v1/records/cases"]["get"]["parameters"]
        .as_array()
        .expect("query parameters are rendered")
        .iter()
        .find(|parameter| parameter["name"] == "pageSize")
        .expect("pageSize parameter is rendered");
    assert_eq!(page_size["required"], false);
    assert_eq!(
        page_size["schema"],
        json!({"type": "integer", "minimum": 1})
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
    assert_no_mutation_methods(&protected_openapi);
    assert_eq!(harness.records.calls(), 0);
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
        registry_server::contract::FieldTypeSource::VocabularyCode { vocabulary, values } => {
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
            .len(),
        1
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
            ["classified-status"],
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
        protected_schema["properties"]["classified-status"],
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
    let missing_profile = body_json(missing_profile_response).await;
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
        assert_eq!(body_json(response).await, missing_profile, "{uri}");
    }

    for uri in ["/v1/vocabularies", "/v1/events", "/v1/queries"] {
        for claims in [None, authorized_claims.clone()] {
            let response = send_to(&app, Method::GET, uri, claims).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(body_json(response).await, missing_profile, "{uri}");
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
        &format!("{list_path}?accessProfile=caseworker&pageSize=1"),
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
    assert!(revisions.refusals.load(Ordering::SeqCst) >= 3);

    revisions.refusal_fails.store(true, Ordering::SeqCst);
    let audit_failure = send_to(
        &app,
        Method::GET,
        &format!("{list_path}?pageSize=2"),
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
    registry: &registry_server::CompiledRegistry,
    entity_id: &str,
    access_profile: &str,
) -> Value {
    let metadata_entity = registry
        .metadata()
        .entities
        .iter()
        .find(|entity| entity.id == entity_id)
        .expect("compiled metadata entity exists");
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
        Operation::Create => "create",
        Operation::Patch => "patch",
        Operation::Tombstone => "tombstone",
        Operation::Batch => "batch",
        Operation::Revisions => "revisions",
    }
}

#[tokio::test]
async fn every_compiled_mutation_route_is_absent_from_the_served_router() {
    let harness = Harness::new(true);
    let claims = Some(caseworker_claims("case-management"));
    for (method, uri) in [
        (Method::POST, "/v1/records/cases"),
        (Method::PATCH, "/v1/records/cases/record-1"),
        (Method::DELETE, "/v1/records/cases/record-1"),
        (Method::POST, "/v1/records/cases:batch"),
        (Method::GET, "/v1/records/cases/record-1/revisions"),
        (Method::POST, "/v1/records/notes"),
        (Method::PATCH, "/v1/records/notes/record-1"),
        (Method::DELETE, "/v1/records/notes/record-1"),
    ] {
        let response = harness.send(method, uri, claims.clone()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(body_json(response).await["code"], "resource.not_found");
    }
    assert_eq!(harness.records.calls(), 0);
}

fn caseworker_claims(purpose: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "principal-value-never-rendered",
        BTreeSet::from(["registry.read".to_owned()]),
        Some(purpose.to_owned()),
        BTreeMap::from([(
            "jurisdictions".to_owned(),
            VerifiedClaimValue::direct_string_set(["area-a", "area-b"]).expect("direct claims"),
        )]),
    )
    .expect("verified context")
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

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("JSON response")
}

fn assert_no_mutation_methods(document: &Value) {
    for path in document["paths"].as_object().unwrap().values() {
        let methods = path.as_object().unwrap();
        assert!(methods.get("post").is_none());
        assert!(methods.get("patch").is_none());
        assert!(methods.get("delete").is_none());
    }
}
