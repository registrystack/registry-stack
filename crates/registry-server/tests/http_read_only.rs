// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{header::CONTENT_TYPE, Method, Request, StatusCode};
use registry_platform_canonical_json::parse_json_strict;
use registry_server::api::{
    router, HeldReadResponse, HttpService, ReadRuntimeIdentity, ReadServiceError, ReadinessProbe,
    RecordReadKind, RecordReadRequest, RecordReadService, RevisionReadRefusal, RevisionReadRequest,
    RevisionReadService, ServiceFuture, VerifiedClaimValue, VerifiedRequestClaims,
};
use registry_server::artifacts::REGISTRY_METADATA_ARTIFACT_PATH;
use registry_server::contract::{ModuleAssetSource, Operation};
use registry_server::cursor::CursorCodec;
use registry_server::{
    compile_project, compile_project_with_assets, parse_project_yaml, CompileProfile,
};
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
        allowCount: true
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

const LOOKUP_PATH_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: lookup-path-surface
  version: 0.1.0
  defaultLanguage: en
entities:
  - id: household
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
    accessProfiles:
      - id: operator
        default: true
        principalClaim: registry_principal
        requiredScopes: [registry.read]
        requiredPurposes: [case-management]
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
      - id: viewer
        principalClaim: registry_principal
        requiredScopes: [registry.read]
        requiredPurposes: [case-management]
        operations: [get, lookup]
        readableFields: [household-code]
        rowBoundaries:
          - {field: id, claim: household_id, operator: equals}
        lookups:
          - selector: by-household-code
            valueOrigin: verified_claim
            claimMapping: {household-code: household_code}
  - id: membership
    route: memberships
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: household, type: reference, target: household, required: true, classification: restricted}
      - {id: person, type: reference, target: person, required: true, classification: restricted}
  - id: person
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
        operations: [get, list]
        readableFields: [sensitive-note]
        filterableFields: [sensitive-note]
        sortableFields: [sensitive-note]
"#;

const DERIVED_DISCOVERY_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: derived-discovery
  version: 0.1.0
  defaultLanguage: en
entities:
  - id: benefit-record
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

const LOGICAL_SCHEMA_PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: logical-schema-surface
  version: 1
  defaultLanguage: en
entities:
  - id: logical-record
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
        operations: [get, list]
        readableFields: [household-code, household-kind-code]
vocabularies:
  - id: household-kind
    values: [single, extended]
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
        registry_server::api::ReadFilterOperator::StartsWith
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
    let accepted = harness
        .send_json(
            Method::POST,
            "/v1/records/households:lookup?accessProfile=operator&$select=household-code",
            operator_claims.clone(),
            json!({
                "selector": "by-local-reference",
                "values": {
                    "administrative-area": "area-a",
                    "local-household-number": 7
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
        json!({"selector": "by-local-reference", "values": {"administrative-area": "area-a", "local-household-number": "7"}}),
        json!({"selector": "by-local-reference", "values": {"administrative-area": "area-a", "local-household-number": 7, "private-note": "DO-NOT-LEAK"}}),
        json!({"selector": "by-local-reference", "values": {"administrative-area": "area-a", "local-household-number": 7}, "extra": "DO-NOT-LEAK"}),
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
        r#"{{"selector":"by-household-code","values":{{"household-code":"{}"}}}}"#,
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
            json!({"selector": "missing-canary", "values": {"household-code": "DO-NOT-LEAK"}}),
        )
        .await;
    let unknown_body = body_bytes(unknown).await;
    let ungranted = harness
        .send_json(
            Method::POST,
            "/v1/records/households:lookup?accessProfile=operator",
            operator_claims.clone(),
            json!({"selector": "by-private-note", "values": {"private-note": "DO-NOT-LEAK"}}),
        )
        .await;
    let ungranted_body = body_bytes(ungranted).await;
    assert_eq!(unknown_body, ungranted_body);
    assert!(!String::from_utf8_lossy(&unknown_body).contains("DO-NOT-LEAK"));
    assert_eq!(
        serde_json::from_slice::<Value>(&unknown_body).expect("unresolved response is JSON")
            ["code"],
        "lookup.unresolved"
    );

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
        registry_server::contract::LookupValueOrigin::VerifiedClaim
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
            json!({"selector": "by-household-code", "values": {"household-code": "DO-NOT-LEAK"}}),
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
    assert_eq!(body_bytes(missing_claim).await, unknown_body);
}

#[tokio::test]
async fn relationship_route_uses_path_grant_not_direct_target_rights() {
    let harness = Harness::from_project(LOOKUP_PATH_PROJECT, true);
    let root = "00000000-0000-4000-8000-000000000001";
    let accepted = harness
        .send(
            Method::GET,
            &format!(
                "/v1/records/households/{root}/people?accessProfile=operator&$select=person-code&$filter=startswith(person-code,'P-')&$orderby=person-code&$top=5&$count=true"
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
                "/v1/records/households/{root}/people?accessProfile=operator&$select=sensitive-note"
            ),
            Some(caseworker_claims("case-management")),
        )
        .await;
    assert_eq!(widened.status(), StatusCode::BAD_REQUEST);
    let widened_body = body_json(widened).await;
    assert_eq!(widened_body["code"], "query.invalid");
    assert!(!widened_body.to_string().contains("sensitive-note"));
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
    let unknown_path_body = body_json(unknown_path).await;

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
    assert_eq!(body_json(ungranted).await, unknown_path_body);
    assert_eq!(harness.records.calls(), before);
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
        .contains(&registry_server::model::CompiledQueryFilterOperator::Contains));

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
            "person-code": {"type": "string", "minLength": 0, "maxLength": 64},
            "sensitive-note": {"type": "string", "minLength": 0, "maxLength": 64}
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
        .get("household-code")
        .is_some());
    assert!(household_schema["properties"].get("person-code").is_none());

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
        schema["properties"]["eligibility-score"],
        json!({"type": "integer", "format": "int64", "readOnly": true})
    );
    assert_eq!(
        schema["properties"]["label"],
        json!({"type": "string", "minLength": 0, "maxLength": 100})
    );
    assert_eq!(schema["required"], json!(["label"]));

    let response = send_to(
        &app,
        Method::GET,
        "/v1/records/benefit-records/00000000-0000-4000-8000-000000000001?accessProfile=operator&$select=eligibility-score",
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
        .send(Method::GET, "/v1/records/cases?$filter=label%20eq", None)
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(response).await["code"], "source.unavailable");
    assert_eq!(harness.records.calls(), 0);
    assert_eq!(harness.records.refusal_calls(), 1);
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
async fn select_id_is_a_noop_and_filter_grouping_reaches_the_plan() {
    let harness = Harness::new(true);
    let selected_id = harness
        .send(Method::GET, "/v1/records/cases?$select=id", None)
        .await;
    assert_eq!(selected_id.status(), StatusCode::OK);
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
        Some(registry_server::api::ReadFilterExpr::Binary {
            op: registry_server::api::ReadLogicalOp::And,
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

    fn list(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        let selected_fields = request.selected_fields.clone();
        let maximum_records = request.maximum_records;
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
                            "jurisdiction": "area-a"
                    }
                }),
                &selected_fields,
            )];
            records.truncate(maximum_records);
            let mut response = json!({"items": records, "pageInfo": {"nextCursor": null}});
            if include_count {
                response["count"] = json!(1);
            }
            Ok(held(response))
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
            "accessProfile",
        ]
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
    ] {
        let refused = harness.send(Method::GET, uri, None).await;
        assert_eq!(refused.status(), StatusCode::NOT_FOUND, "{uri}");
        let problem = body_json(refused).await;
        assert_eq!(problem["code"], "resource.not_found");
        let rendered = problem.to_string();
        assert!(!rendered.contains("unknownCanary"));
        assert!(!rendered.contains("privateCanary"));
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
    assert!(revisions.refusals.load(Ordering::SeqCst) >= 3);

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
        Operation::Lookup => "lookup",
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

fn request_query(request: &RecordReadRequest) -> &registry_server::api::CompiledReadQuery {
    match &request.kind {
        RecordReadKind::List { plan } | RecordReadKind::Relationship { plan, .. } => plan,
        RecordReadKind::Get { .. } | RecordReadKind::Lookup { .. } => {
            panic!("request did not carry a list query plan")
        }
    }
}

fn single_filter_predicate(
    query: &registry_server::api::CompiledReadQuery,
) -> &registry_server::api::ReadFilterPredicate {
    match query.filter.as_ref().expect("query has a filter") {
        registry_server::api::ReadFilterExpr::Predicate(predicate) => predicate,
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

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    bytes.to_vec()
}

async fn body_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&body_bytes(response).await).expect("JSON response")
}

fn assert_no_mutation_methods(document: &Value) {
    for path in document["paths"].as_object().unwrap().values() {
        let methods = path.as_object().unwrap();
        assert!(methods.get("post").is_none());
        assert!(methods.get("patch").is_none());
        assert!(methods.get("delete").is_none());
    }
}
