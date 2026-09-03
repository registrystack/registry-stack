// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::compiler::{compile_project, CompileProfile};
use crate::contract::parse_project_yaml;
use crate::cursor::CursorCodec;
use crate::model::{CompiledAction, CompiledRegistry};
use crate::postgres::{
    ConnectionConfig, ExpectedRegistryIdentity, PoolBounds, PostgresRecordMutationService,
    RegistryLockKey,
};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry: {id: action-admission, version: "1", defaultLanguage: en, canonicalBaseIri: https://action-admission.example.test}
entities:
  - id: case
    primaryDataset: test-dataset
    route: cases
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: label, type: string, maxLength: 40, required: true, classification: restricted}
      - {id: region, type: string, maxLength: 20, required: true, classification: internal}
actions:
  - id: rename-case
    inputs:
      - {id: case-ref, apiName: caseId, type: reference, target: case, required: true, classification: restricted}
      - {id: case-label, apiName: newLabel, type: string, maxLength: 40, required: true, classification: restricted}
    effects:
      - id: renamed
        target: {fromField: case-ref}
        operation: patch
        set: {label: {fromField: case-label}}
accessProfiles:
  - id: registrar
    default: true
    principalClaim: registry_principal
    requiredScopes: [case.rename]
    requiredPurposes: [case-management]
    grants:
      - action: rename-case
        operations: [invoke]
        targets:
          - entity: case
            rowBoundaries: [{field: region, claim: regions, operator: in}]
        results: [renamed]
  - id: supervisor
    principalClaim: registry_principal
    requiredScopes: [case.supervise]
    requiredPurposes: [case-management]
    grants:
      - action: rename-case
        operations: [invoke]
        targets: [{entity: case, rowBoundaries: []}]
        results: []
"#;

fn compiled() -> Arc<CompiledRegistry> {
    let project = parse_project_yaml(PROJECT.as_bytes()).expect("action fixture parses");
    Arc::new(
        compile_project(&project, &[], CompileProfile::Authoring).expect("action fixture compiles"),
    )
}

#[test]
fn invocation_uses_public_names_and_a_closed_typed_envelope() {
    let registry = compiled();
    let action = &registry.actions().actions[0];
    let body = br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#;
    let parsed = parse_body(action, ActionRouteKind::Invoke, body).unwrap();
    assert_eq!(parsed.input["case-label"], "Changed");
    assert!(parsed.input.contains_key("case-ref"));
    assert_eq!(parsed.preconditions["case-ref"], "\"opaque\"");

    for refused in [
        br#"{"input":{"case-ref":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#.as_slice(),
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":4},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\"","revision":1}}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"*"}}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}},"results":["renamed"]}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed","newLabel":"Duplicate"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#,
    ] {
        assert!(parse_body(action, ActionRouteKind::Invoke, refused).is_err());
    }
}

#[test]
fn malformed_action_body_reports_only_safe_field_paths() {
    let registry = compiled();
    let action = &registry.actions().actions[0];

    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001"}}"#
        ),
        "/input/newLabel"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":4},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#
        ),
        "/input/newLabel"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed","secret_claim":"north"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}}}"#
        ),
        "/input"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"}}"#
        ),
        "/preconditions"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"*"}}}"#
        ),
        "/preconditions/caseId/ifMatch"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\"","secret_claim":"north"}}}"#
        ),
        "/preconditions/caseId"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"secret_claim":"north"}}}"#
        ),
        "/preconditions/caseId"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"secret_claim":{"ifMatch":"\"opaque\""}}}"#
        ),
        "/preconditions"
    );
    assert_eq!(
        parse_error_path(
            action,
            ActionRouteKind::Invoke,
            br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"},"preconditions":{"caseId":{"ifMatch":"\"opaque\""}},"secret_claim":"north"}"#
        ),
        ""
    );
}

#[test]
fn field_paths_escape_declared_public_input_names() {
    assert_eq!(
        json_pointer(["input", "declared/name~with~tilde"]),
        "/input/declared~1name~0with~0tilde"
    );
}

#[tokio::test]
async fn correlated_action_problem_preserves_safe_field_path() {
    let response = invalid_action_request(ParseActionError::at("/input/newLabel"));
    let correlation = crate::correlation::RequestCorrelation::breg_created();
    let response =
        crate::correlation::finish_response(response, &correlation, "POST", Instant::now());
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body = parse_json_strict(&bytes).unwrap();
    assert_eq!(body["code"], "request.invalid");
    assert_eq!(body["fieldPath"], "/input/newLabel");
    assert_eq!(body["traceId"], correlation.trace_id().as_str());
}

#[test]
fn condition_read_accepts_only_exact_patch_role_identifiers() {
    let registry = compiled();
    let action = &registry.actions().actions[0];
    let parsed = parse_body(
        action,
        ActionRouteKind::TargetConditions,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001"}}"#,
    )
    .unwrap();
    assert_eq!(parsed.input.len(), 1);
    assert!(parsed.preconditions.is_empty());
    for refused in [
        br#"{"input":{}}"#.as_slice(),
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001","newLabel":"Changed"}}"#,
        br#"{"input":{"caseId":"not-a-record"}}"#,
        br#"{"input":{"caseId":"00000000-0000-4000-8000-000000000001"},"preconditions":{}}"#,
        br#"{"input":{"caseId":["00000000-0000-4000-8000-000000000001"]}}"#,
    ] {
        assert!(parse_body(action, ActionRouteKind::TargetConditions, refused).is_err());
    }
}

fn parse_error_path(action: &CompiledAction, kind: ActionRouteKind, body: &[u8]) -> String {
    match parse_body(action, kind, body) {
        Ok(_) => panic!("body is refused"),
        Err(error) => error.field_path,
    }
}

#[test]
fn action_authority_has_no_crud_requirement_or_profile_fallback() {
    let registry = compiled();
    assert!(registry.routes().routes.is_empty());
    let service = service_for(registry.clone(), true);
    let route = registry
        .actions()
        .routes
        .iter()
        .find(|route| route.kind == ActionRouteKind::Invoke)
        .unwrap();
    let authorized_claims = claims(
        "registry_principal",
        ["case.rename"],
        Some("case-management"),
        true,
    );
    let surface = authorize_action(
        &service,
        route,
        &authorized_claims,
        &QueryOptions::default(),
    )
    .unwrap();
    assert_eq!(surface.context.selected_profile(), "registrar");
    assert_eq!(
        surface.context.result_effects(),
        &BTreeSet::from(["renamed".to_owned()])
    );
    assert_eq!(
        surface.context.target_authority()["case"][0].field(),
        "region"
    );
    let supervisor = claims(
        "registry_principal",
        ["case.supervise"],
        Some("case-management"),
        false,
    );
    assert!(authorize_action(&service, route, &supervisor, &QueryOptions::default()).is_none());
    let explicit = QueryOptions::parse(Some("accessProfile=supervisor"), false).unwrap();
    assert!(authorize_action(&service, route, &supervisor, &explicit)
        .unwrap()
        .context
        .result_effects()
        .is_empty());
    for denied in [
        VerifiedRequestClaims::anonymous(),
        claims("sub", ["case.rename"], Some("case-management"), true),
        claims("registry_principal", ["case.rename"], None, true),
        claims(
            "registry_principal",
            ["case.rename"],
            Some("other-purpose"),
            true,
        ),
        claims(
            "registry_principal",
            ["case.rename"],
            Some("case-management"),
            false,
        ),
    ] {
        assert!(authorize_action(&service, route, &denied, &QueryOptions::default()).is_none());
    }
    let mut forged = route.clone();
    forged.path.push_str("/forged");
    assert!(authorize_action(
        &service,
        &forged,
        &authorized_claims,
        &QueryOptions::default()
    )
    .is_none());
    assert!(visible_actions(
        &service_for(registry, false),
        &authorized_claims,
        &QueryOptions::default()
    )
    .is_empty());
}

#[tokio::test]
async fn action_only_discovery_is_profile_filtered_without_entity_read_access() {
    let registry = compiled();
    let service = Arc::new(service_for(registry, true));
    let registrar = claims(
        "registry_principal",
        ["case.rename"],
        Some("case-management"),
        true,
    );
    let supervisor = claims(
        "registry_principal",
        ["case.supervise"],
        Some("case-management"),
        false,
    );

    let response = super::super::registry_metadata(
        State(service.clone()),
        Some(Extension(registrar)),
        RawQuery(None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["entities"], json!([]));
    assert_eq!(body["actions"][0]["id"], "rename-case");
    assert_eq!(
        body["actions"][0]["requiredConditionKeys"],
        json!(["caseId"])
    );
    assert!(!body.to_string().contains("registry_principal"));
    assert!(!body.to_string().contains("rowBoundaries"));

    let response = super::super::openapi(
        State(service.clone()),
        Some(Extension(supervisor)),
        RawQuery(Some("accessProfile=supervisor".to_owned())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert!(body["paths"]["/v1/actions/rename-case"]["post"].is_object());
    assert!(body["paths"]["/v1/actions/rename-case/target-conditions"]["post"].is_object());
    assert!(body["paths"]
        .as_object()
        .unwrap()
        .keys()
        .all(|path| path.starts_with("/v1/actions/")));
    let result_schema = crate::artifacts::openapi_action_response_schema_id("rename-case");
    assert_eq!(
        body["components"]["schemas"][&result_schema]["properties"]["results"]["properties"],
        json!({})
    );
    assert!(!body.to_string().contains("registrar"));

    // An anonymous caller with no visible operation or action receives the
    // same value-free 404 as on record routes.
    let anonymous =
        super::super::registry_metadata(State(service.clone()), None, RawQuery(None)).await;
    assert_eq!(anonymous.status(), StatusCode::NOT_FOUND);
    let refused = super::super::openapi(
        State(service),
        None,
        RawQuery(Some("accessProfile=supervisor".to_owned())),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::NOT_FOUND);
}

async fn response_json(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    parse_json_strict(&bytes).unwrap()
}

fn claims<const N: usize>(
    name: &str,
    scopes: [&str; N],
    purpose: Option<&str>,
    boundary: bool,
) -> VerifiedRequestClaims {
    let direct = if boundary {
        BTreeMap::from([(
            "regions".to_owned(),
            VerifiedClaimValue::direct_string_set(["north"]).unwrap(),
        )])
    } else {
        BTreeMap::new()
    };
    VerifiedRequestClaims::authenticated(
        name,
        "synthetic-registrar",
        scopes.into_iter().map(str::to_owned).collect(),
        purpose.map(str::to_owned),
        direct,
    )
    .unwrap()
}

fn service_for(registry: Arc<CompiledRegistry>, mutations: bool) -> HttpService {
    let duration = Duration::from_secs(1);
    let service = HttpService::new(
        registry.clone(),
        ReadRuntimeIdentity {
            package_revision: "package-revision".to_owned(),
            schema_fingerprint: "schema-fingerprint".to_owned(),
        },
        Arc::new(NoopRecords),
        Arc::new(Ready),
        Arc::new(CursorCodec::new(Zeroizing::new(vec![7; 32]), duration).unwrap()),
    );
    if !mutations {
        return service;
    }
    // Pool construction performs no database I/O. HTTP execution is tested by
    // the real PostgreSQL action journey; these tests exercise admission only.
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let pool = ConnectionConfig::require_tls_with_custom_ca(
        "postgresql://action_test@localhost/action-admission",
        certificate.cert.der(),
        PoolBounds::new(1, duration, duration, duration).unwrap(),
    )
    .unwrap()
    .build_pool()
    .unwrap();
    service.with_postgres_mutations(Arc::new(PostgresRecordMutationService::new(
        pool,
        registry,
        ExpectedRegistryIdentity {
            package_id: "test".to_owned(),
            environment: "test".to_owned(),
            instance_id: "test".to_owned(),
            database_id: "test".to_owned(),
            package_revision: "package-revision".to_owned(),
            schema_fingerprint: "schema-fingerprint".to_owned(),
            package_sequence: 1,
        },
        RegistryLockKey::derive("action-admission").unwrap(),
        duration,
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x81; 32].into())
            .unwrap(),
    )))
}

struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
struct NoopRecords;
impl RecordReadService for NoopRecords {
    fn get(
        &self,
        _: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }
    fn list(
        &self,
        _: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        Box::pin(async { Err(ReadServiceError::Unavailable) })
    }
    fn lookup(
        &self,
        _: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        Box::pin(async { Ok(None) })
    }
    fn refusal(&self, _: RecordReadRefusal) -> ServiceFuture<'_, Result<(), ReadServiceError>> {
        Box::pin(async { Ok(()) })
    }
}
