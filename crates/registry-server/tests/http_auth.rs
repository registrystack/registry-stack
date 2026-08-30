// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderValue, Request, StatusCode};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    JwksFetcher, JwksFetcherConfig, OidcError, TokenVerifier, TokenVerifierConfig,
};
use registry_platform_testing::{
    fixtures, oidc_verifier_config, sign_ed25519_compact_jwt, MockIdp,
};
use registry_server::api::{
    authenticated_router, HeldReadResponse, HttpService, ReadRuntimeIdentity, ReadServiceError,
    ReadinessProbe, RecordReadRequest, RecordReadService, ServiceFuture, VerifiedRequestClaims,
};
use registry_server::auth::{
    AuthenticationConfigError, AuthenticationError, AuthorityClaimConfig, RegistryAuthenticator,
    RowBoundaryClaimMapping, RowBoundaryClaimType,
};
use registry_server::cursor::CursorCodec;
use registry_server::{compile_project, parse_project_yaml, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use zeroize::Zeroizing;

const AUDIENCE: &str = "urn:example:registry-server";
const PRINCIPAL: &str = "principal-value-never-rendered";
const PURPOSE: &str = "case-management-never-rendered";
const JURISDICTION: &str = "area-a-never-rendered";
const TENANT: &str = "tenant-a-never-rendered";

const PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: authenticated-read-surface
  version: 0.1.0
  defaultLanguage: en
entities:
  - id: case
    route: cases
    mutationMode: mutable
    tombstone: false
    classification: public
    fields:
      - {id: label, type: string, required: true, maxLength: 100, classification: public}
      - {id: secret, type: string, required: true, maxLength: 100, classification: restricted}
      - {id: jurisdiction, type: string, required: true, maxLength: 100, classification: internal}
      - {id: tenant, type: string, required: true, maxLength: 100, classification: internal}
    accessProfiles:
      - id: public
        default: true
        anonymous: true
        operations: [get]
        readableFields: [label]
      - id: caseworker
        principalClaim: registry_principal
        requiredScopes: [registry.read]
        requiredPurposes: [case-management-never-rendered]
        operations: [get]
        readableFields: [label, secret]
        rowBoundaries:
          - {field: jurisdiction, claim: jurisdictions, operator: in}
          - {field: tenant, claim: tenant, operator: equals}
"#;

#[derive(Default)]
struct RecordingReadService {
    calls: AtomicUsize,
    requests: Mutex<Vec<RecordReadRequest>>,
}

impl RecordReadService for RecordingReadService {
    fn get(
        &self,
        request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
        let selected_fields = request.selected_fields.clone();
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().expect("record requests").push(request);
        Box::pin(async move {
            Ok(Some(held(project_fixture(
                json!({
                    "id": "case-1",
                    "revision": 1,
                    "data": {
                        "label": "Visible",
                        "secret": "SECRET-RESPONSE-CANARY"
                    }
                }),
                &selected_fields,
            ))))
        })
    }

    fn list(
        &self,
        _request: RecordReadRequest,
    ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(held(json!({"items": []}))) })
    }
}

fn held(value: Value) -> HeldReadResponse {
    HeldReadResponse::from_json(&value).expect("fake read response serializes")
}

fn project_fixture(mut record: Value, selected_fields: &BTreeSet<String>) -> Value {
    record["data"]
        .as_object_mut()
        .expect("fixture data is an object")
        .retain(|field, _| selected_fields.contains(field));
    record
}

struct Ready;

impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

struct Harness {
    app: axum::Router,
    authenticator: Arc<RegistryAuthenticator>,
    records: Arc<RecordingReadService>,
    registry: Arc<CompiledRegistry>,
    idp: MockIdp,
}

impl Harness {
    async fn new() -> Self {
        let registry = compiled_registry();
        let idp = MockIdp::start().await;
        let authenticator = authenticator(&registry, &idp, authority_claims())
            .expect("authentication config is valid");
        let records = Arc::new(RecordingReadService::default());
        let service = Arc::new(HttpService::new(
            Arc::clone(&registry),
            read_identity(),
            records.clone(),
            Arc::new(Ready),
            cursor_codec(),
        ));
        let authenticator = Arc::new(authenticator);
        let app = authenticated_router(service, Arc::clone(&authenticator));
        Self {
            app,
            authenticator,
            records,
            registry,
            idp,
        }
    }

    async fn send(
        &self,
        uri: &str,
        authorization: &[HeaderValue],
        injected_claims: Option<VerifiedRequestClaims>,
    ) -> axum::response::Response {
        let mut request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        for value in authorization {
            request.headers_mut().append(AUTHORIZATION, value.clone());
        }
        if let Some(claims) = injected_claims {
            request.extensions_mut().insert(claims);
        }
        self.app
            .clone()
            .oneshot(request)
            .await
            .expect("router responds")
    }

    fn valid_token(&self) -> String {
        self.idp.mint_token(valid_claims())
    }

    fn signed_token(&self, mut claims: Value, typ: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs();
        let claims = claims
            .as_object_mut()
            .expect("fixture claims are an object");
        claims
            .entry("iss")
            .or_insert_with(|| json!(self.idp.issuer()));
        claims.entry("iat").or_insert_with(|| json!(now));
        claims.entry("nbf").or_insert_with(|| json!(now));
        claims.entry("exp").or_insert_with(|| json!(now + 900));
        sign_ed25519_compact_jwt(
            fixtures::ED25519_PRIVATE_JWK,
            typ,
            "registry-platform-testing-ed25519-1",
            Value::Object(claims.clone()),
        )
    }
}

fn read_identity() -> ReadRuntimeIdentity {
    ReadRuntimeIdentity {
        package_revision: "package-auth-test".to_owned(),
        schema_fingerprint: "schema-auth-test".to_owned(),
    }
}

fn cursor_codec() -> Arc<CursorCodec> {
    Arc::new(
        CursorCodec::new(
            Zeroizing::new(vec![0x43; 32]),
            std::time::Duration::from_secs(300),
        )
        .expect("test cursor key is valid"),
    )
}

#[tokio::test]
async fn verified_direct_authority_reaches_the_protected_record_service() {
    let harness = Harness::new().await;
    let token = harness.valid_token();
    let response = harness
        .send(
            "/v1/records/cases/case-1?accessProfile=caseworker",
            &[bearer(&token)],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["data"]["secret"], "SECRET-RESPONSE-CANARY");
    assert_eq!(harness.records.calls.load(Ordering::SeqCst), 1);

    let requests = harness.records.requests.lock().expect("record requests");
    let context = &requests[0].context;
    assert_eq!(context.principal(), Some(PRINCIPAL));
    assert_eq!(context.purpose(), Some(PURPOSE));
    assert_eq!(context.row_boundaries().len(), 2);
    assert_eq!(
        context
            .row_boundaries()
            .iter()
            .find(|boundary| boundary.field() == "jurisdiction")
            .expect("jurisdiction boundary")
            .values(),
        &BTreeSet::from([JURISDICTION.to_owned()])
    );
    assert_eq!(
        context
            .row_boundaries()
            .iter()
            .find(|boundary| boundary.field() == "tenant")
            .expect("tenant boundary")
            .values(),
        &BTreeSet::from([TENANT.to_owned()])
    );
}

#[tokio::test]
async fn missing_malformed_or_fallback_only_principal_is_refused_before_record_io() {
    let harness = Harness::new().await;
    let mut cases = Vec::new();
    let mut missing = valid_claims();
    missing
        .as_object_mut()
        .unwrap()
        .remove("registry_principal");
    cases.push(harness.signed_token(missing, "JWT"));
    for value in [json!([PRINCIPAL]), json!({"id": PRINCIPAL}), Value::Null] {
        let mut claims = valid_claims();
        claims["registry_principal"] = value;
        cases.push(harness.signed_token(claims, "JWT"));
    }
    let mut fallback_only = valid_claims();
    fallback_only
        .as_object_mut()
        .unwrap()
        .remove("registry_principal");
    fallback_only["sub"] = json!(PRINCIPAL);
    fallback_only["client_id"] = json!(PRINCIPAL);
    fallback_only["azp"] = json!(PRINCIPAL);
    cases.push(harness.signed_token(fallback_only, "JWT"));

    for token in cases {
        assert_refused_without_record_call(&harness, &token).await;
    }
}

#[tokio::test]
async fn malformed_purpose_and_row_boundary_shapes_are_refused_before_record_io() {
    let harness = Harness::new().await;
    let malformed = [
        ("purpose", json!([PURPOSE])),
        ("purpose", Value::Null),
        ("jurisdictions", json!(JURISDICTION)),
        ("jurisdictions", json!([])),
        ("jurisdictions", json!([JURISDICTION, {"id": JURISDICTION}])),
        ("tenant", json!([TENANT])),
        ("tenant", Value::Null),
    ];
    for (name, value) in malformed {
        let mut claims = valid_claims();
        claims[name] = value;
        let token = harness.signed_token(claims, "JWT");
        assert_refused_without_record_call(&harness, &token).await;
    }
}

#[tokio::test]
async fn issuer_audience_algorithm_token_type_and_signature_are_all_verified() {
    let harness = Harness::new().await;
    let mut wrong_issuer = valid_claims();
    wrong_issuer["iss"] = json!("https://issuer.invalid/URL-CREDENTIAL-CANARY");
    let wrong_issuer = harness.signed_token(wrong_issuer, "JWT");

    let mut wrong_audience = valid_claims();
    wrong_audience["iss"] = json!(harness.idp.issuer());
    wrong_audience["aud"] = json!("urn:wrong:AUDIENCE-CANARY");
    let wrong_audience = harness.signed_token(wrong_audience, "JWT");

    let mut correctly_issued = valid_claims();
    correctly_issued["iss"] = json!(harness.idp.issuer());
    let wrong_type = harness.signed_token(correctly_issued.clone(), "id_token");
    let signed = harness.signed_token(correctly_issued, "JWT");
    let wrong_algorithm = format!(
        "{}.{}",
        "eyJhbGciOiJSUzI1NiIsImtpZCI6InJlZ2lzdHJ5LXBsYXRmb3JtLXRlc3RpbmctZWQyNTUxOS0xIiwidHlwIjoiSldUIn0",
        signed.split_once('.').expect("compact token").1
    );
    let mut wrong_signature = signed;
    let signature_start = wrong_signature.rfind('.').expect("signature separator") + 1;
    let replacement = if wrong_signature.as_bytes()[signature_start] == b'A' {
        "B"
    } else {
        "A"
    };
    wrong_signature.replace_range(signature_start..=signature_start, replacement);

    let verifier = token_verifier(&harness.idp);
    verifier
        .key_source()
        .ensure_key_set()
        .await
        .expect("MockIdP JWKS is reachable before verifier-negative assertions");
    assert_platform_refusal(&verifier, &wrong_issuer, |error| {
        matches!(error, OidcError::IssuerMismatch { .. })
    })
    .await;
    assert_platform_refusal(&verifier, &wrong_audience, |error| {
        matches!(error, OidcError::AudienceMismatch)
    })
    .await;
    assert_platform_refusal(&verifier, &wrong_algorithm, |error| {
        matches!(error, OidcError::AlgorithmNotAllowed)
    })
    .await;
    assert_platform_refusal(&verifier, &wrong_type, |error| {
        matches!(error, OidcError::TokenTypeNotAllowed)
    })
    .await;
    assert_platform_refusal(&verifier, &wrong_signature, |error| {
        matches!(error, OidcError::SignatureInvalid)
    })
    .await;

    for token in [
        wrong_issuer,
        wrong_audience,
        wrong_algorithm,
        wrong_type,
        wrong_signature,
    ] {
        assert_refused_without_record_call(&harness, &token).await;
    }
}

#[tokio::test]
async fn malformed_or_duplicate_bearer_never_downgrades_to_anonymous() {
    let harness = Harness::new().await;
    for values in [
        vec![HeaderValue::from_static("Bearer malformed")],
        vec![HeaderValue::from_static("Bearer  malformed")],
        vec![
            HeaderValue::from_static("Bearer one.two.three"),
            HeaderValue::from_static("Bearer four.five.six"),
        ],
    ] {
        let before = harness.records.calls.load(Ordering::SeqCst);
        let response = harness
            .send("/v1/records/cases/case-1", &values, None)
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(response).await["code"], "authentication.refused");
        assert_eq!(harness.records.calls.load(Ordering::SeqCst), before);
    }
}

#[tokio::test]
async fn anonymous_without_a_token_succeeds_but_injected_authority_is_removed() {
    let harness = Harness::new().await;
    let public = harness.send("/v1/records/cases/case-1", &[], None).await;
    assert_eq!(public.status(), StatusCode::OK);
    assert_eq!(body_json(public).await["data"], json!({"label": "Visible"}));

    let before = harness.records.calls.load(Ordering::SeqCst);
    let missing = harness
        .send(
            "/v1/records/cases/case-1?accessProfile=caseworker",
            &[],
            None,
        )
        .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(harness.records.calls.load(Ordering::SeqCst), before);

    let injected = VerifiedRequestClaims::authenticated(
        "registry_principal",
        PRINCIPAL,
        BTreeSet::from(["registry.read".to_owned()]),
        Some(PURPOSE.to_owned()),
        BTreeMap::new(),
    )
    .expect("low-level fixture claims");
    let before = harness.records.calls.load(Ordering::SeqCst);
    let response = harness
        .send(
            "/v1/records/cases/case-1?accessProfile=caseworker",
            &[],
            Some(injected),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(harness.records.calls.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn refusals_and_debug_output_are_value_free() {
    let harness = Harness::new().await;
    let mut claims = valid_claims();
    claims["iss"] = json!(harness.idp.issuer());
    claims["registry_principal"] = json!({"value": PRINCIPAL});
    let token = harness.signed_token(claims, "JWT");
    let error = harness
        .authenticator
        .authenticate(&token)
        .await
        .expect_err("malformed authority claim is refused");
    assert_eq!(error, AuthenticationError::InvalidClaims);
    let error_debug = format!("{error:?}");
    let authenticator_debug = format!("{:?}", harness.authenticator);

    let before = harness.records.calls.load(Ordering::SeqCst);
    let response = harness
        .send("/v1/records/cases/case-1", &[bearer(&token)], None)
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await.to_string();
    assert_eq!(harness.records.calls.load(Ordering::SeqCst), before);
    for canary in [
        PRINCIPAL,
        PURPOSE,
        JURISDICTION,
        TENANT,
        AUDIENCE,
        harness.idp.issuer().as_str(),
        token.as_str(),
        "URL-CREDENTIAL-CANARY",
    ] {
        assert!(!body.contains(canary), "problem body exposed {canary}");
        assert!(
            !error_debug.contains(canary),
            "error Debug exposed {canary}"
        );
        assert!(
            !authenticator_debug.contains(canary),
            "authenticator Debug exposed {canary}"
        );
    }
}

#[tokio::test]
async fn constructor_rejects_empty_duplicate_reserved_and_incomplete_mappings() {
    let harness = Harness::new().await;
    let invalid = [
        AuthorityClaimConfig::new("", Some("purpose".to_owned()), row_claims()),
        AuthorityClaimConfig::new("sub", Some("purpose".to_owned()), row_claims()),
        AuthorityClaimConfig::new(
            "registry_principal",
            Some("registry_principal".to_owned()),
            row_claims(),
        ),
        AuthorityClaimConfig::new(
            "registry_principal",
            Some("purpose".to_owned()),
            vec![
                RowBoundaryClaimMapping::new(
                    "jurisdictions",
                    RowBoundaryClaimType::DirectStringSet,
                ),
                RowBoundaryClaimMapping::new(
                    "jurisdictions",
                    RowBoundaryClaimType::DirectStringSet,
                ),
            ],
        ),
    ];
    for claims in invalid {
        let error = authenticator(&harness.registry, &harness.idp, claims)
            .expect_err("unsafe claim mapping is refused");
        assert_eq!(error, AuthenticationConfigError::InvalidClaimMapping);
    }

    for claims in [
        AuthorityClaimConfig::new("registry_principal", None, row_claims()),
        AuthorityClaimConfig::new(
            "registry_principal",
            Some("purpose".to_owned()),
            vec![RowBoundaryClaimMapping::new(
                "jurisdictions",
                RowBoundaryClaimType::DirectStringSet,
            )],
        ),
        AuthorityClaimConfig::new(
            "registry_principal",
            Some("purpose".to_owned()),
            vec![
                RowBoundaryClaimMapping::new("jurisdictions", RowBoundaryClaimType::DirectString),
                RowBoundaryClaimMapping::new("tenant", RowBoundaryClaimType::DirectString),
            ],
        ),
    ] {
        let error = authenticator(&harness.registry, &harness.idp, claims)
            .expect_err("incomplete compiled authority mapping is refused");
        assert_eq!(error, AuthenticationConfigError::CompiledAuthorityMismatch);
    }
}

#[tokio::test]
async fn constructor_requires_one_exact_bounded_verifier_profile() {
    let harness = Harness::new().await;
    let mut empty_issuer = verifier_config(&harness.idp);
    empty_issuer.issuer = " ".to_owned();
    let mut duplicate_audience = verifier_config(&harness.idp);
    duplicate_audience.audiences.push(AUDIENCE.to_owned());
    let mut duplicate_algorithm = verifier_config(&harness.idp);
    duplicate_algorithm
        .allowed_algorithms
        .push(duplicate_algorithm.allowed_algorithms[0]);
    let mut duplicate_type = verifier_config(&harness.idp);
    duplicate_type.allowed_typ.push("at+jwt".to_owned());
    let mut reserved_scope = verifier_config(&harness.idp);
    reserved_scope.scope_claim = "sub".to_owned();

    for verifier in [
        empty_issuer,
        duplicate_audience,
        duplicate_algorithm,
        duplicate_type,
        reserved_scope,
    ] {
        let error = authenticator_with_verifier(
            &harness.registry,
            &harness.idp,
            verifier,
            authority_claims(),
        )
        .expect_err("ambiguous verifier profile is refused");
        assert_eq!(error, AuthenticationConfigError::InvalidVerifierProfile);
    }
}

async fn assert_refused_without_record_call(harness: &Harness, token: &str) {
    let before = harness.records.calls.load(Ordering::SeqCst);
    let response = harness
        .send(
            "/v1/records/cases/case-1?accessProfile=caseworker",
            &[bearer(token)],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(response).await;
    assert_eq!(body["code"], "authentication.refused");
    assert_eq!(harness.records.calls.load(Ordering::SeqCst), before);
}

async fn assert_platform_refusal(
    verifier: &TokenVerifier,
    token: &str,
    expected: impl FnOnce(&OidcError) -> bool,
) {
    let error = verifier
        .verify(token)
        .await
        .expect_err("platform verifier refused token");
    assert!(expected(&error), "unexpected platform verifier refusal");
}

fn authenticator(
    registry: &CompiledRegistry,
    idp: &MockIdp,
    claims: AuthorityClaimConfig,
) -> Result<RegistryAuthenticator, AuthenticationConfigError> {
    authenticator_with_verifier(registry, idp, verifier_config(idp), claims)
}

fn authenticator_with_verifier(
    registry: &CompiledRegistry,
    idp: &MockIdp,
    verifier: TokenVerifierConfig,
    claims: AuthorityClaimConfig,
) -> Result<RegistryAuthenticator, AuthenticationConfigError> {
    let key_source = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    RegistryAuthenticator::new(registry, verifier, key_source, claims)
}

fn token_verifier(idp: &MockIdp) -> TokenVerifier {
    TokenVerifier::new(verifier_config(idp), key_source(idp))
}

fn key_source(idp: &MockIdp) -> Arc<JwksFetcher> {
    Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ))
}

fn verifier_config(idp: &MockIdp) -> TokenVerifierConfig {
    oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()])
}

fn authority_claims() -> AuthorityClaimConfig {
    AuthorityClaimConfig::new(
        "registry_principal",
        Some("purpose".to_owned()),
        row_claims(),
    )
}

fn row_claims() -> Vec<RowBoundaryClaimMapping> {
    vec![
        RowBoundaryClaimMapping::new("jurisdictions", RowBoundaryClaimType::DirectStringSet),
        RowBoundaryClaimMapping::new("tenant", RowBoundaryClaimType::DirectString),
    ]
}

fn valid_claims() -> Value {
    json!({
        "aud": AUDIENCE,
        "registry_principal": PRINCIPAL,
        "scope": "registry.read",
        "purpose": PURPOSE,
        "jurisdictions": [JURISDICTION],
        "tenant": TENANT,
    })
}

fn compiled_registry() -> Arc<CompiledRegistry> {
    let project = parse_project_yaml(PROJECT.as_bytes()).expect("project parses");
    Arc::new(compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles"))
}

fn bearer(token: &str) -> HeaderValue {
    format!("Bearer {token}").parse().expect("bearer header")
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("JSON response")
}
